from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from analyzer.platform import detect_platform
from analyzer.taint import TaintSink
from analyzer.wordpress import scan_plugin, scan_plugin_with_taint
from duplicate_checker import is_duplicate, record_finding
from main import _coverage_after_timeout, main, scan_source_path, scan_target
from reporter.json_report import write_json_report
from reporter.patchstack import append_v5_report


class PlatformDetectionTests(unittest.TestCase):
    def test_detects_platform_markers(self) -> None:
        marker_by_platform = {
            "wordpress": "wp-config.php",
            "laravel": "artisan",
            "django": "manage.py",
            "nodejs": "package.json",
        }
        for platform, marker in marker_by_platform.items():
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                (root / marker).touch()
                self.assertEqual(detect_platform(root), platform)

    def test_php_plugin_without_wp_config_is_wordpress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "plugin.php").write_text("<?php", encoding="utf-8")
            self.assertEqual(detect_platform(root), "wordpress")

    def test_non_wordpress_marker_inside_ignored_directory_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            marker = root / "vendor" / "package" / "package.json"
            marker.parent.mkdir(parents=True)
            marker.touch()
            self.assertIsNone(detect_platform(root))

    def test_conflicting_markers_are_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "artisan").touch()
            (root / "manage.py").touch()
            self.assertIsNone(detect_platform(root))


class ExistingWordPressFilterTests(unittest.TestCase):
    def test_synthetic_vuln_test_keeps_one_potential_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "test.php").write_text(
                "<?php\n"
                "if (isset($_FILES['f'])) {\n"
                "    move_uploaded_file($_FILES['f']['tmp_name'], '/tmp/test');\n"
                "}\n",
                encoding="utf-8",
            )
            findings = scan_plugin(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["type"], "Unauthenticated File Upload")

    def test_vendor_only_synthetic_plugin_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            vendor_file = root / "vendor" / "package" / "upload.php"
            vendor_file.parent.mkdir(parents=True)
            vendor_file.write_text(
                "<?php if (isset($_FILES['f'])) { move_uploaded_file($_FILES['f']['tmp_name'], '/tmp/test'); }",
                encoding="utf-8",
            )
            self.assertEqual(scan_plugin(root), [])

    def test_auth_check_exactly_50_lines_before_is_annotated_not_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            lines = ["<?php current_user_can('upload');"]
            lines.extend("// filler" for _ in range(49))
            lines.append("$file = $_FILES['upload'];")
            (root / "plugin.php").write_text("\n".join(lines), encoding="utf-8")

            findings = scan_plugin(root)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "POTENTIAL")
            self.assertTrue(findings[0]["auth_present"])


class TaintScannerModeTests(unittest.TestCase):
    def test_timeout_coverage_marks_unconfirmed_files_skipped(self) -> None:
        coverage = {
            "complete": True,
            "discovered_php_files": 2,
            "php_files_by_status": {"scanned": 2},
            "php_files_by_classification": {"first_party": 2},
            "files": [
                {
                    "kind": "php_file",
                    "path": "one.php",
                    "status": "scanned",
                    "classification": "first_party",
                    "reason": "",
                },
                {
                    "kind": "php_file",
                    "path": "vendor/lib.php",
                    "status": "intentionally_excluded",
                    "classification": "third_party",
                    "reason": "classified as third-party dependency code",
                },
            ],
            "non_file_issues": [],
            "incomplete_reasons": [],
            "intentional_exclusions": [],
        }

        result = _coverage_after_timeout(coverage, "analysis timed out")

        self.assertFalse(result["complete"])
        self.assertEqual(
            result["php_files_by_status"],
            {"skipped": 1, "intentionally_excluded": 1},
        )
        self.assertEqual(result["files"][0]["reason"], "analysis timed out")
        self.assertEqual(result["incomplete_reasons"][0]["path"], "one.php")

    def test_v5_markdown_escapes_untrusted_text_and_deduplicates_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            reports = Path(temporary_directory)
            findings = [
                {
                    "type": "XSS\n## injected heading",
                    "file": "src`/plugin.php",
                    "line": 7,
                    "function": "handler`name",
                    "confidence": "medium",
                    "trace": [
                        {
                            "kind": "source",
                            "name": "$_GET `",
                            "file": "src`/plugin.php",
                            "line": 2,
                        }
                    ],
                    "sanitizer_evidence": [],
                    "auth_evidence": [],
                    "note": "review\n## injected note",
                }
            ]
            audit = [
                {
                    "reason": "effective sanitizer\n## injected reason",
                    "original_confidence": "medium",
                    "downgraded_confidence": "low",
                    "sanitizer_evidence": [],
                    "auth_evidence": [],
                    "finding": findings[0],
                }
            ]

            report_path = append_v5_report(
                "fixture",
                findings,
                audit,
                reports,
            )
            self.assertIsNotNone(report_path)
            assert report_path is not None
            rendered = report_path.read_text(encoding="utf-8")
            original_bytes = report_path.read_bytes()
            append_v5_report("fixture", findings, audit, reports)

            self.assertIn("source: $_GET", rendered)
            self.assertIn("``handler`name``", rendered)
            self.assertNotIn("\n## injected heading", rendered)
            self.assertNotIn("\n## injected note", rendered)
            self.assertNotIn("\n## injected reason", rendered)
            self.assertEqual(report_path.read_bytes(), original_bytes)

    def test_taint_mode_markdown_reports_trace_evidence_and_downgrade_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "report-plugin"
            source.mkdir()
            (source / "vuln.php").write_text(
                "<?php\n"
                "function show(){ $id = $_GET['id']; echo $id; }\n"
                "function safe(){ $id = sanitize_text_field($_GET['id']); "
                "echo esc_html($id); }\n",
                encoding="utf-8",
            )
            reports = root / "reports"

            result = scan_source_path(
                source,
                engine="taint",
                reports_dir=reports,
            )

            report_path = reports / "report-plugin" / "report_patchstack.md"
            markdown = report_path.read_text(encoding="utf-8")
            json_report = json.loads(
                (reports / "report-plugin" / "report_json.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(result.exit_code, 1)
            self.assertEqual(len(json_report["v5_taint_findings"]), 1)
            self.assertEqual(len(json_report["v5_audit"]), 1)
            self.assertTrue(json_report["v5_coverage"]["complete"])
            self.assertEqual(json_report["v5_coverage"]["discovered_php_files"], 1)
            self.assertEqual(
                json_report["v5_coverage"]["php_files_by_status"], {"scanned": 1}
            )
            self.assertIn("## V5 Taint Analysis", markdown)
            self.assertIn("Cross-Site Scripting (XSS)", markdown)
            self.assertIn("$_GET", markdown)
            self.assertIn("echo", markdown)
            self.assertIn("vuln.php:2", markdown)
            self.assertIn("**Confidence:** medium", markdown)
            self.assertIn("**Trace:** line 2 `$_GET` ->", markdown)
            self.assertIn("**Why it matters:**", markdown)
            self.assertIn("**Fix suggestion:**", markdown)
            self.assertIn("Sanitizer evidence", markdown)
            self.assertIn("Authorization evidence", markdown)
            self.assertIn("## V5 Audit (`v5_audit`)", markdown)
            self.assertIn("effective sanitizer", markdown)
            self.assertIn("function `safe`", markdown)
            self.assertIn("## V5 Coverage", markdown)
            self.assertIn("**Coverage complete:** yes", markdown)
            self.assertIn("**PHP file statuses:** scanned: 1", markdown)

    def test_mass_folder_scan_adds_taint_fields_and_preserves_history_dedupe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "mass-plugin"
            source.mkdir()
            (source / "one.php").write_text(
                "<?php function output(){ echo $_GET['x']; }",
                encoding="utf-8",
            )
            (source / "includes").mkdir()
            (source / "includes" / "two.php").write_text(
                "<?php function run_query(){ $wpdb->query($_POST['sql']); }",
                encoding="utf-8",
            )
            (source / "vendor" / "library").mkdir(parents=True)
            (source / "vendor" / "library" / "ignored.php").write_text(
                "<?php echo $_GET['vendor'];",
                encoding="utf-8",
            )
            reports = root / "reports"
            first = scan_source_path(source, engine="taint", reports_dir=reports)
            report_path = reports / "mass-plugin" / "report_json.json"
            first_report = json.loads(report_path.read_text(encoding="utf-8"))
            history = (reports / "history.json").read_bytes()

            second = scan_source_path(source, engine="taint", reports_dir=reports)
            second_report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertEqual(first.exit_code, 1)
            self.assertEqual(second.exit_code, 1)
            self.assertEqual(
                {item["type"] for item in first_report["findings"]},
                {"Unauthenticated SQL Injection"},
            )
            self.assertEqual(
                {item["type"] for item in second_report["findings"]},
                {"Unauthenticated SQL Injection"},
            )
            self.assertEqual(len(first_report["v5_taint_findings"]), 2)
            coverage = first_report["v5_coverage"]
            self.assertTrue(coverage["complete"])
            self.assertEqual(coverage["discovered_php_files"], 3)
            self.assertEqual(
                coverage["php_files_by_status"],
                {"intentionally_excluded": 1, "scanned": 2},
            )
            self.assertEqual(
                coverage["intentional_exclusions"][0]["path"],
                "vendor/library/ignored.php",
            )
            markdown = (
                reports / "mass-plugin" / "report_patchstack.md"
            ).read_text(encoding="utf-8")
            self.assertIn("Intentionally excluded PHP files", markdown)
            self.assertIn("vendor/library/ignored.php", markdown)
            self.assertEqual((reports / "history.json").read_bytes(), history)

    def test_mass_zip_scan_uses_safe_extraction_and_v4_regex_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive = root / "mass.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr(
                    "package/plugin.php",
                    "<?php $file = $_FILES['upload'];",
                )
                zipped.writestr(
                    "package/includes/other.php",
                    "<?php $wpdb->query($_POST['value']);",
                )
            reports = root / "reports"
            temp_root = Path(tempfile.gettempdir())
            extraction_dirs_before = set(
                temp_root.glob("hunter-os-mass-mass-*")
            )

            result = scan_source_path(archive, engine="regex", reports_dir=reports)

            report = json.loads(
                (reports / "mass" / "report_json.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result.exit_code, 1)
            self.assertIsInstance(report, list)
            self.assertEqual(
                {item["type"] for item in report},
                {"Unauthenticated File Upload", "Unauthenticated SQL Injection"},
            )
            self.assertEqual(
                set(temp_root.glob("hunter-os-mass-mass-*")),
                extraction_dirs_before,
            )

    def test_taint_mass_scan_handles_malformed_empty_and_oversized_php(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "bounded"
            source.mkdir()
            (source / "empty.php").write_text("", encoding="utf-8")
            (source / "broken.php").write_text(
                "<?php function broken(){ echo $_GET['x'];",
                encoding="utf-8",
            )
            (source / "large.php").write_bytes(b"x" * 10_000_000)

            result = scan_source_path(
                source,
                engine="taint",
                reports_dir=root / "reports",
            )

            report = json.loads(
                (root / "reports" / "bounded" / "report_json.json").read_text(
                    encoding="utf-8"
                )
            )
            markdown = (
                root / "reports" / "bounded" / "report_patchstack.md"
            ).read_text(encoding="utf-8")
            self.assertEqual(result.exit_code, 1)
            self.assertTrue(any(
                finding["type"] == "Incomplete taint analysis"
                for finding in report["v5_taint_findings"]
            ))
            self.assertTrue(any(
                "incomplete parse" in finding["note"].casefold()
                for finding in report["v5_taint_findings"]
                if finding["type"] == "Incomplete taint analysis"
            ))
            warning_files = {
                item["finding"]["file"]
                for item in report["v5_audit"]
                if item["reason"].startswith("analysis incomplete")
            }
            self.assertEqual(
                warning_files,
                {"empty.php", "broken.php", "large.php"},
            )
            self.assertFalse(report["v5_coverage"]["complete"])
            self.assertEqual(
                report["v5_coverage"]["php_files_by_status"],
                {"oversized": 1, "unsupported": 2},
            )
            self.assertEqual(
                {item["path"] for item in report["v5_coverage"]["incomplete_reasons"]},
                {"empty.php", "broken.php", "large.php"},
            )
            self.assertIn("**Coverage complete:** no", markdown)
            self.assertIn("**Coverage gaps:**", markdown)
            self.assertIn("empty.php", markdown)
            self.assertIn("source limit", markdown)

    def test_taint_mass_scan_surfaces_timeout_and_file_count_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "limited"
            source.mkdir()
            (source / "one.php").write_text(
                "<?php echo $_GET['x'];",
                encoding="utf-8",
            )
            (source / "two.php").write_text(
                "<?php echo $_POST['x'];",
                encoding="utf-8",
            )

            with patch("analyzer.wordpress.time.monotonic", side_effect=[0.0, 2.0]):
                timed_out = scan_plugin_with_taint(source, timeout_seconds=1)
            self.assertFalse(timed_out.complete)
            self.assertTrue(any(
                item["code"] == "timeout" for item in timed_out.diagnostics
            ))

            reports = root / "reports"
            with patch("main.MAX_MASS_SCAN_FILES", 1):
                limited = scan_source_path(
                    source,
                    engine="taint",
                    reports_dir=reports,
                )
            report = json.loads(
                (reports / "limited" / "report_json.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(limited.exit_code, 1)
            self.assertTrue(any(
                item["type"] == "Incomplete taint analysis"
                and "file analysis limit" in item["note"]
                for item in report["v5_taint_findings"]
            ))
            self.assertTrue(any(
                item["finding"]["file"] == "<scan>"
                for item in report["v5_audit"]
            ))

    def test_taint_per_file_timeout_is_preserved_in_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory)
            (source / "slow.php").write_text(
                "<?php echo $_GET['value'];",
                encoding="utf-8",
            )
            with patch(
                "analyzer.wordpress.time.perf_counter",
                side_effect=[0.0, 6.0],
            ):
                result = scan_plugin_with_taint(source)

            self.assertFalse(result.complete)
            self.assertTrue(any(
                item["code"] == "per_file_timeout"
                for item in result.diagnostics
            ))
            self.assertTrue(any(
                item["finding"]["file"] == "slow.php"
                and "Per-file taint analysis exceeded" in item["note"]
                for item in result.audit
            ))

    def test_real_file_wordpress_entrypoints_cover_ajax_shortcode_and_rest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "framework.php"
            source.write_text(
                "<?php\n"
                "add_action('wp_ajax_nopriv_delete', 'delete_post');\n"
                "function delete_post(){ wp_delete_post($_GET['id']); }\n"
                "add_action('wp_ajax_remove', 'guarded_delete');\n"
                "function guarded_delete(){ "
                "if (!current_user_can('delete_posts')) { return; } "
                "wp_delete_post($_GET['id']); }\n"
                "add_action('wp_ajax_nopriv_nonce', 'nonce_delete');\n"
                "function nonce_delete(){ "
                "check_ajax_referer('delete'); wp_delete_post($_GET['id']); }\n"
                "add_shortcode('public_value', 'shortcode_value');\n"
                "function shortcode_value(){ echo $_GET['value']; }\n"
                "register_rest_route('demo/v1', '/missing', ["
                "'methods' => 'GET', 'callback' => 'rest_missing']);\n"
                "function rest_missing(){ $id = $_GET['id']; wp_delete_post($id); }\n"
                "register_rest_route('demo/v1', '/open', ["
                "'methods' => 'GET', 'callback' => 'rest_open', "
                "'permission_callback' => '__return_true']);\n"
                "function rest_open(){ $id = $_GET['id']; wp_delete_post($id); }\n"
                "register_rest_route('demo/v1', '/protected', ["
                "'methods' => 'GET', 'callback' => 'rest_protected', "
                "'permission_callback' => 'can_delete']);\n"
                "function can_delete(){ return current_user_can('delete_posts'); }\n"
                "function rest_protected(){ $id = $_GET['id']; wp_delete_post($id); }\n",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "main.py"),
                    "--engine=taint",
                    str(source),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["findings"], [])
            active = report["v5_taint_findings"]
            audit = report["v5_audit"]
            ajax = [
                item for item in active
                if item["type"] == "Unauthenticated WordPress AJAX Action"
            ]
            self.assertEqual(
                {item["function"] for item in ajax},
                {"delete_post", "nonce_delete"},
            )
            nonce = next(item for item in ajax if item["function"] == "nonce_delete")
            self.assertIn("nonce is not auth", nonce["note"])
            guarded = [
                item for item in audit
                if item["finding"].get("function") == "guarded_delete"
                and item["finding"].get("type")
                == "Unauthenticated WordPress AJAX Action"
            ]
            self.assertEqual(len(guarded), 1)

            xss = [
                item for item in active
                if item["type"] == "Cross-Site Scripting (XSS)"
            ]
            shortcode_xss = next(
                item for item in xss if item.get("function") == "shortcode_value"
            )
            self.assertTrue(
                any(entry["type"] == "shortcode" for entry in shortcode_xss["entry_points"])
            )

            rest_findings = [
                item for item in active
                if item["type"] == "WordPress REST Route Authorization"
            ]
            self.assertEqual(
                {item["entry_point_details"]["route"] for item in rest_findings},
                {"/missing", "/open"},
            )
            self.assertTrue(
                all("tainted" in item["note"].casefold() for item in rest_findings)
            )
            protected_action = [
                item for item in audit
                if item["finding"].get("function") == "rest_protected"
                and item["finding"].get("type")
                == "Sensitive State-Changing Action"
            ]
            self.assertEqual(len(protected_action), 1)
            self.assertTrue(protected_action[0]["finding"]["auth_evidence"])

    def test_rest_permission_proof_does_not_cover_same_callback_open_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "shared_callback.php"
            source.write_text(
                "<?php\n"
                "register_rest_route('demo/v1', '/protected', ["
                "'callback' => 'shared_delete', 'permission_callback' => 'can_delete']);\n"
                "register_rest_route('demo/v1', '/open', ["
                "'callback' => 'shared_delete', 'permission_callback' => '__return_true']);\n"
                "function can_delete(){ return current_user_can('delete_posts'); }\n"
                "function shared_delete(){ wp_delete_post($_GET['id']); }\n",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "main.py"),
                    "--engine=taint",
                    str(source),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            report = json.loads(completed.stdout)
            routes = [
                item for item in report["v5_taint_findings"]
                if item["type"] == "WordPress REST Route Authorization"
            ]
            self.assertEqual(
                {item["entry_point_details"]["route"] for item in routes}, {"/open"}
            )

    def test_closure_body_is_never_reported_as_clean_when_not_analyzed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "closure.php"
            source.write_text(
                "<?php $callback = function(){ echo $_GET['value']; };",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "main.py"),
                    "--engine=taint",
                    str(source),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            report = json.loads(completed.stdout)
            incomplete = [
                item for item in report["v5_taint_findings"]
                if item["type"] == "Incomplete taint analysis"
            ]
            self.assertEqual(len(incomplete), 1)
            self.assertEqual(incomplete[0]["confidence"], "low")
            self.assertIn("closure", incomplete[0]["note"].casefold())
            self.assertTrue(any(
                item["finding"]["type"] == "Incomplete taint analysis"
                for item in report["v5_audit"]
            ))

    def test_ajax_authorization_checks_each_sensitive_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "ajax.php"
            source.write_text(
                "<?php\n"
                "add_action('wp_ajax_nopriv_delete', 'handle_delete');\n"
                "function handle_delete(){\n"
                "  if (current_user_can('delete_posts')) wp_delete_post(1);\n"
                "  wp_delete_user($_POST['id']);\n"
                "}\n",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "main.py"),
                    "--engine=taint",
                    str(source),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            report = json.loads(completed.stdout)
            ajax_findings = [
                item for item in report["v5_taint_findings"]
                if item["type"] == "Unauthenticated WordPress AJAX Action"
            ]
            self.assertEqual(len(ajax_findings), 1)
            self.assertEqual(ajax_findings[0]["sink"]["name"], "wp_delete_user")
            self.assertEqual(ajax_findings[0]["line"], 5)
            self.assertFalse(ajax_findings[0]["auth_evidence"])
            protected = [
                item["finding"] for item in report["v5_audit"]
                if item.get("finding", {}).get("type")
                == "Unauthenticated WordPress AJAX Action"
            ]
            self.assertEqual(len(protected), 1)
            self.assertEqual(protected[0]["sink"]["name"], "wp_delete_post")
            self.assertTrue(protected[0]["auth_evidence"])

    def test_rest_permission_requires_authorization_on_every_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "routes.php"
            source.write_text(
                "<?php\n"
                "register_rest_route('demo/v1', '/conditional', ["
                "'callback' => 'delete_conditional', 'permission_callback' => 'maybe_delete']);\n"
                "register_rest_route('demo/v1', '/protected', ["
                "'callback' => 'delete_protected', 'permission_callback' => 'can_delete']);\n"
                "function maybe_delete(){\n"
                "  if ($_GET['check']) return current_user_can('delete_posts');\n"
                "  return true;\n"
                "}\n"
                "function can_delete(){ return current_user_can('delete_posts'); }\n"
                "function delete_conditional($request){ wp_delete_post($request['id']); }\n"
                "function delete_protected($request){ wp_delete_post($request['id']); }\n",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "main.py"),
                    "--engine=taint",
                    str(source),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            report = json.loads(completed.stdout)
            rest_findings = [
                item for item in report["v5_taint_findings"]
                if item["type"] == "WordPress REST Route Authorization"
            ]
            self.assertEqual(
                {item["entry_point_details"]["route"] for item in rest_findings},
                {"/conditional"},
            )
            finding = rest_findings[0]
            self.assertEqual(finding["sink"]["name"], "wp_delete_post")
            self.assertFalse(finding["auth_evidence"])
            protected_action = [
                item["finding"] for item in report["v5_audit"]
                if item.get("finding", {}).get("function") == "delete_protected"
                and item.get("finding", {}).get("type")
                == "Sensitive State-Changing Action"
            ]
            self.assertTrue(any(item["auth_evidence"] for item in protected_action))

    def test_sanitizer_argument_and_context_proofs_are_sink_specific(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "contexts.php"
            source.write_text(
                "<?php\n"
                "function output(){\n"
                "  echo esc_html($_GET['safe']);\n"
                "  echo '<script>const x=\"' . esc_html($_GET['js']) . '\";</script>';\n"
                "  echo '<a href=\"' . esc_html($_GET['bad_url']) . '\">';\n"
                "  echo '<a href=\"' . esc_url($_GET['safe_url']) . '\">';\n"
                "  echo '<div title=\"' . esc_html($_GET['bad_attr']) . '\">';\n"
                "  echo '<div title=\"' . esc_attr($_GET['safe_attr']) . '\">';\n"
                "  echo '<button onclick=\"' . esc_attr($_GET['event']) . '\">';\n"
                "  echo '<div style=\"' . esc_attr($_GET['style']) . '\">';\n"
                "  $safe_unlocated = esc_html($_GET['unknown_context']);\n"
                "  echo $safe_unlocated;\n"
                "  echo esc_html('constant', $_GET['unused']);\n"
                "}\n"
                "function query(){\n"
                "  $wpdb->query('SELECT * FROM t ORDER BY ' . esc_sql($_GET['sort']));\n"
                "  $wpdb->query($wpdb->prepare('SELECT * FROM t WHERE id=%d', $_GET['id']));\n"
                "}\n",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "main.py"),
                    "--engine=taint",
                    str(source),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            report = json.loads(completed.stdout)
            active = report["v5_taint_findings"]
            xss_active = [
                item for item in active
                if item["type"] == "Cross-Site Scripting (XSS)"
            ]
            self.assertEqual(len(xss_active), 6)
            self.assertEqual(
                {item["context"] for item in xss_active},
                {"javascript", "url", "html_attribute", "unknown_output", "css"},
            )
            self.assertTrue(all(
                item["sanitizer_evidence"]
                and not item["sanitizer_evidence"][0]["effective"]
                for item in xss_active
            ))
            sql = [
                item for item in active if item["type"] == "SQL Injection"
            ]
            self.assertEqual(len(sql), 1)
            self.assertTrue(sql[0]["sanitizer_evidence"])
            self.assertFalse(sql[0]["sanitizer_evidence"][0]["effective"])
            audit_findings = [
                item["finding"] for item in report["v5_audit"]
                if isinstance(item.get("finding"), dict)
            ]
            self.assertTrue(any(
                item["type"] == "Cross-Site Scripting (XSS)"
                and item["context"] == "html"
                and item["status"] == "DOWNGRADED"
                for item in audit_findings
            ))
            self.assertTrue(any(
                item["type"] == "Cross-Site Scripting (XSS)"
                and item["context"] == "url"
                and item["status"] == "DOWNGRADED"
                and any(
                    evidence["name"] == "esc_url" and evidence["effective"]
                    for evidence in item["sanitizer_evidence"]
                )
                for item in audit_findings
            ))
            self.assertTrue(any(
                item["type"] == "Cross-Site Scripting (XSS)"
                and item["context"] == "html_attribute"
                and item["status"] == "DOWNGRADED"
                and any(
                    evidence["name"] == "esc_attr" and evidence["effective"]
                    for evidence in item["sanitizer_evidence"]
                )
                for item in audit_findings
            ))
            self.assertTrue(any(
                item["type"] == "SQL Injection"
                and item["status"] == "DOWNGRADED"
                and any(
                    evidence["name"] == "$wpdb->prepare" and evidence["effective"]
                    for evidence in item["sanitizer_evidence"]
                )
                for item in audit_findings
            ))

    def test_real_file_cli_reports_only_unsanitized_xss(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "vuln.php"
            source.write_text(
                "<?php\n"
                "function show(){ $id = $_GET['id']; echo $id; }\n"
                "function safe(){ $id = sanitize_text_field($_GET['id']); "
                "echo esc_html($id); }\n",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "main.py"),
                    "--engine=taint",
                    str(source),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["findings"], [])
            self.assertEqual(len(report["v5_taint_findings"]), 1)
            finding = report["v5_taint_findings"][0]
            self.assertEqual(finding["type"], "Cross-Site Scripting (XSS)")
            self.assertEqual(finding["function"], "show")
            self.assertEqual(finding["source"]["name"], "$_GET")
            self.assertEqual(finding["sink"]["name"], "echo")
            trace = finding["trace"]
            self.assertEqual(trace[0]["name"], "$_GET")
            self.assertTrue(any(step["name"] == "$id" for step in trace))
            self.assertTrue(any(step["name"] == "echo" for step in trace))
            self.assertEqual(len(report["v5_audit"]), 1)
            self.assertEqual(report["v5_audit"][0]["finding"]["function"], "safe")
            self.assertEqual(
                report["v5_audit"][0]["finding"]["status"], "DOWNGRADED"
            )

    def test_real_file_sqli_source_reaches_database_query(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "query.php").write_text(
                "<?php function search(){ "
                "$id = $_GET['id']; $wpdb->query('SELECT * FROM t WHERE id=' . $id); }",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            self.assertIn("SQL Injection", {item["type"] for item in result.findings})
            finding = next(
                item for item in result.findings if item["type"] == "SQL Injection"
            )
            self.assertEqual(finding["source"]["name"], "$_GET")
            self.assertEqual(finding["sink"]["name"], "$wpdb->query")

    def test_real_file_print_is_an_xss_output_sink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "print.php").write_text(
                "<?php function output(){ print $_REQUEST['value']; }",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            xss = [
                item for item in result.findings
                if item["type"] == "Cross-Site Scripting (XSS)"
            ]
            self.assertEqual(len(xss), 1)
            self.assertEqual(xss[0]["sink"]["name"], "print")

    def test_real_file_prepared_sqli_is_audited_not_reported_as_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "prepared.php").write_text(
                "<?php function search(){ $id = $_GET['id']; "
                "$wpdb->query($wpdb->prepare('SELECT * FROM t WHERE id=%s', $id)); }",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            prepared = [
                item for item in result.findings if item["type"] == "SQL Injection"
            ]
            self.assertEqual(len(prepared), 1)
            self.assertEqual(prepared[0]["status"], "DOWNGRADED")
            self.assertTrue(prepared[0]["sanitizer_evidence"])
            self.assertEqual(result.audit[0]["reason"], "effective sanitizer")

    def test_real_file_ajax_nopriv_sensitive_action_requires_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "ajax.php").write_text(
                "<?php\n"
                "add_action('wp_ajax_nopriv_update', 'handle_update');\n"
                "function handle_update(){ update_option('site_name', $_POST['name']); }\n",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            ajax_findings = [
                item for item in result.findings if "AJAX" in item["type"]
            ]
            self.assertEqual(len(ajax_findings), 1)
            self.assertEqual(ajax_findings[0]["type"], "Unauthenticated WordPress AJAX Action")
            self.assertEqual(ajax_findings[0]["sink"]["name"], "update_option")

    def test_real_file_ajax_nonce_is_not_authorization_but_guard_is_audited(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "nonce_only.php").write_text(
                "<?php\n"
                "add_action('wp_ajax_nopriv_nonce', 'nonce_handler');\n"
                "function nonce_handler(){ "
                "check_ajax_referer('nonce'); update_option('name', 'value'); }\n",
                encoding="utf-8",
            )
            (root / "guarded.php").write_text(
                "<?php\n"
                "add_action('wp_ajax_nopriv_guarded', 'guarded_handler');\n"
                "function guarded_handler(){ "
                "if (!current_user_can('manage_options')) { return; } "
                "update_option('name', 'value'); }\n",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            ajax_findings = [
                item for item in result.findings
                if item["type"] == "Unauthenticated WordPress AJAX Action"
            ]
            nonce_only = next(
                item for item in ajax_findings if item["function"] == "nonce_handler"
            )
            guarded = next(
                item for item in ajax_findings if item["function"] == "guarded_handler"
            )
            self.assertTrue(nonce_only["nonce_evidence"])
            self.assertFalse(nonce_only["auth_evidence"])
            self.assertEqual(nonce_only["status"], "POTENTIAL")
            self.assertTrue(guarded["auth_evidence"])
            self.assertEqual(guarded["status"], "DOWNGRADED")
            self.assertTrue(any(
                item["finding"]["function"] == "guarded_handler"
                for item in result.audit
            ))

    def test_real_file_upload_flags_file_reaching_upload_api_not_reference_alone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "upload.php").write_text(
                "<?php function receive(){ "
                "move_uploaded_file($_FILES['upload']['tmp_name'], '/tmp/file'); }\n",
                encoding="utf-8",
            )
            (root / "reference_only.php").write_text(
                "<?php function inspect(){ $file = $_FILES['upload']; }\n",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            uploads = [
                item for item in result.findings if item["type"] == "Unsafe File Upload"
            ]
            self.assertEqual(len(uploads), 1)
            self.assertEqual(uploads[0]["file"], "upload.php")
            self.assertEqual(uploads[0]["sink"]["name"], "move_uploaded_file")

    def test_real_file_upload_nonce_is_not_auth_but_capability_guard_is_audited(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "nonce.php").write_text(
                "<?php function receive(){ check_admin_referer('upload'); "
                "move_uploaded_file($_FILES['upload']['tmp_name'], '/tmp/file'); }",
                encoding="utf-8",
            )
            (root / "guarded.php").write_text(
                "<?php function receive(){ "
                "if (!current_user_can('upload_files')) { return; } "
                "move_uploaded_file($_FILES['upload']['tmp_name'], '/tmp/file'); }",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            nonce = next(
                item for item in result.findings
                if item["file"] == "nonce.php" and item["type"] == "Unsafe File Upload"
            )
            guarded = next(
                item for item in result.findings
                if item["file"] == "guarded.php" and item["type"] == "Unsafe File Upload"
            )
            self.assertFalse(nonce["auth_evidence"])
            self.assertEqual(nonce["status"], "POTENTIAL")
            self.assertTrue(guarded["auth_evidence"])
            self.assertEqual(guarded["status"], "DOWNGRADED")

    def test_real_file_traversal_user_path_reaches_file_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "read.php").write_text(
                "<?php function read_file(){ "
                "$path = $_GET['path']; file_get_contents($path); }\n",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            traversal = [
                item for item in result.findings
                if item["type"] == "Directory Traversal / Local File Inclusion"
            ]
            self.assertEqual(len(traversal), 1)
            self.assertEqual(traversal[0]["source"]["name"], "$_GET")
            self.assertEqual(traversal[0]["sink"]["name"], "file_get_contents")

    def test_real_file_traversal_requires_path_to_reach_file_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "unrelated.php").write_text(
                "<?php function handler(){ $_GET['path']; file_get_contents('/safe/file'); }",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            self.assertNotIn(
                "Directory Traversal / Local File Inclusion",
                {item["type"] for item in result.findings},
            )

    def test_real_file_command_injection_source_reaches_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "command.php").write_text(
                "<?php function run_command(){ system($_GET['command']); }",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            command_findings = [
                item for item in result.findings
                if item["type"] == "Command Injection"
            ]
            self.assertEqual(len(command_findings), 1)
            self.assertEqual(command_findings[0]["sink"]["name"], "system")

    def test_real_file_ssrf_source_reaches_outbound_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "request.php").write_text(
                "<?php function fetch_remote(){ wp_remote_get($_GET['url']); }",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            ssrf_findings = [
                item for item in result.findings
                if item["type"] == "Server-Side Request Forgery"
            ]
            self.assertEqual(len(ssrf_findings), 1)
            self.assertEqual(ssrf_findings[0]["sink"]["name"], "wp_remote_get")

    def test_real_file_secret_detector_reports_high_confidence_key_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "credentials.php").write_text(
                "<?php\n"
                "$api_key = 'AKIA7N4M9Q2R8X5V3C1B';\n"
                "$password = 'your-password-here';\n",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            secrets = [item for item in result.findings if "Secret" in item["type"]]
            self.assertEqual(len(secrets), 1)
            self.assertEqual(secrets[0]["type"], "Hardcoded Secret")
            self.assertEqual(secrets[0]["line"], 2)
            self.assertEqual(secrets[0]["confidence"], "high")

    def test_real_file_secret_detector_ignores_comment_examples(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "examples.php").write_text(
                "<?php\n"
                "// $api_key = 'AKIA7N4M9Q2R8X5V3C1B';\n"
                "$api_key = 'your-api-key-goes-here';\n",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            self.assertNotIn(
                "Hardcoded Secret", {item["type"] for item in result.findings}
            )

    def test_regex_mode_matches_default_v4_output_and_report_bytes(self) -> None:
        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 11, 4, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            source.mkdir()
            (source / "plugin.php").write_text(
                "<?php\n$file = $_FILES['upload'];\n", encoding="utf-8"
            )
            first_reports = root / "first-reports"
            second_reports = first_reports
            first_output = io.StringIO()
            second_output = io.StringIO()

            def run(engine: str | None, reports: Path, output: io.StringIO):
                with (
                    patch("main.get_plugin_local_or_instructions", return_value=source),
                    patch(
                        "main.scan_plugin_with_taint",
                        side_effect=AssertionError("taint engine must stay disabled"),
                    ),
                    patch(
                        "main.is_duplicate",
                        side_effect=lambda slug, file, line: is_duplicate(
                            slug, file, line, reports
                        ),
                    ),
                    patch(
                        "main.record_finding",
                        side_effect=lambda slug, file, line, reports_dir=None: record_finding(
                            slug, file, line, reports
                        ),
                    ),
                    patch("duplicate_checker.datetime", FixedDateTime),
                    redirect_stdout(output),
                ):
                    if engine is None:
                        return scan_target(
                            "fixture", platform_override="wordpress", reports_dir=reports
                        )
                    return scan_target(
                        "fixture",
                        platform_override="wordpress",
                        reports_dir=reports,
                        engine=engine,
                    )

            default_result = run(None, first_reports, first_output)
            default_json = (first_reports / "fixture" / "report_json.json").read_bytes()
            self.assertIsInstance(json.loads(default_json), list)
            default_markdown = (
                first_reports / "fixture" / "report_patchstack.md"
            ).read_bytes()
            default_history = (first_reports / "history.json").read_bytes()
            default_duplicate_output = io.StringIO()
            run(None, first_reports, default_duplicate_output)
            self.assertEqual(
                (first_reports / "fixture" / "report_patchstack.md").read_bytes(),
                default_markdown,
            )
            self.assertEqual(
                (first_reports / "history.json").read_bytes(), default_history
            )

            shutil.rmtree(first_reports / "fixture")
            (first_reports / "history.json").unlink()
            regex_result = run("regex", second_reports, second_output)
            regex_json = (second_reports / "fixture" / "report_json.json").read_bytes()
            regex_markdown = (
                second_reports / "fixture" / "report_patchstack.md"
            ).read_bytes()
            regex_history = (second_reports / "history.json").read_bytes()
            regex_duplicate_output = io.StringIO()
            run("regex", second_reports, regex_duplicate_output)
            self.assertEqual(
                (second_reports / "fixture" / "report_patchstack.md").read_bytes(),
                regex_markdown,
            )
            self.assertEqual(
                (second_reports / "history.json").read_bytes(), regex_history
            )

            self.assertEqual(default_result.exit_code, regex_result.exit_code)
            self.assertEqual(first_output.getvalue(), second_output.getvalue())
            self.assertEqual(default_json, regex_json)
            self.assertEqual(default_markdown, regex_markdown)
            self.assertEqual(default_history, regex_history)
            self.assertEqual(default_duplicate_output.getvalue(), regex_duplicate_output.getvalue())

    def test_taint_mode_keeps_regex_findings_and_adds_v5_json_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            source.mkdir()
            (source / "plugin.php").write_text(
                "<?php\n"
                "$input = $_GET['value'];\n"
                "$wpdb->query($_POST['value']);\n"
                "$file = $_FILES['upload'];\n",
                encoding="utf-8",
            )
            reports = root / "reports"
            output = io.StringIO()
            with (
                patch("main.get_plugin_local_or_instructions", return_value=source),
                patch("main.is_duplicate", return_value=False),
                patch("main.record_finding", side_effect=lambda *args, **kwargs: None),
                redirect_stdout(output),
            ):
                result = scan_target(
                    "fixture",
                    platform_override="wordpress",
                    reports_dir=reports,
                    engine="taint",
                )

            report = json.loads(
                (reports / "fixture" / "report_json.json").read_text(encoding="utf-8")
            )
            v4_findings = report["findings"]
            self.assertEqual(result.exit_code, 1)
            self.assertIn("Unauthenticated File Upload", {item["type"] for item in v4_findings})
            self.assertIn("Unauthenticated SQL Injection", {item["type"] for item in v4_findings})
            self.assertTrue(report["v5_taint_findings"])
            self.assertEqual(
                set(v4_findings[0]),
                {
                    "file",
                    "line",
                    "type",
                    "confidence",
                    "auth_present",
                    "manual_verification_required",
                    "platform",
                    "status",
                    "evidence",
                },
            )
            taint_finding = report["v5_taint_findings"][0]
            self.assertEqual(taint_finding["source"]["line"], 3)
            self.assertEqual(taint_finding["sink"]["line"], 3)
            self.assertTrue(taint_finding["trace"])
            self.assertIn("confidence", taint_finding)
            self.assertIn("sanitizer_evidence", taint_finding)
            self.assertIn("auth_evidence", taint_finding)
            self.assertIn("v5_audit", report)

    def test_sanitized_taint_flow_is_downgraded_but_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            source.mkdir()
            (source / "plugin.php").write_text(
                "<?php $input = $_GET['value']; "
                "$wpdb->query($wpdb->prepare('SELECT %s', $input));",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(source)

            self.assertEqual(len(result.findings), 1)
            finding = result.findings[0]
            self.assertEqual(finding["status"], "DOWNGRADED")
            self.assertEqual(finding["confidence"], "low")
            self.assertTrue(finding["sanitizer_evidence"])
            self.assertEqual(len(result.audit), 1)
            self.assertEqual(result.audit[0]["reason"], "effective sanitizer")
            self.assertEqual(
                result.audit[0]["finding"]["status"], "DOWNGRADED"
            )

    def test_incomplete_parser_emits_low_confidence_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "broken.php").write_text(
                "<?php function broken($input) { return $_GET['x'];",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            self.assertFalse(result.complete)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0]["confidence"], "low")
            self.assertIn("incomplete parse", result.findings[0]["note"])

    def test_auth_proof_requires_same_function_and_before_sink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "guarded.php").write_text(
                "<?php function handler() {\n"
                "  if (!current_user_can('manage_options')) { return; }\n"
                "  $input = $_GET['x'];\n"
                "  $wpdb->query($input);\n"
                "}\n",
                encoding="utf-8",
            )
            (root / "token_only.php").write_text(
                "<?php function handler_three() {\n"
                "  current_user_can('manage_options');\n"
                "  $input = $_GET['x'];\n"
                "  $wpdb->query($input);\n"
                "}\n",
                encoding="utf-8",
            )
            (root / "unrelated.php").write_text(
                "<?php current_user_can('manage_options');\n"
                "function handler_two() {\n"
                "  $input = $_GET['x'];\n"
                "  $wpdb->query($input);\n"
                "}\n",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            guarded = [item for item in result.findings if item["file"] == "guarded.php"]
            unrelated = [item for item in result.findings if item["file"] == "unrelated.php"]
            token_only = [item for item in result.findings if item["file"] == "token_only.php"]
            self.assertTrue(guarded[0]["auth_evidence"])
            self.assertEqual(guarded[0]["status"], "DOWNGRADED")
            self.assertFalse(unrelated[0]["auth_evidence"])
            self.assertEqual(unrelated[0]["status"], "POTENTIAL")
            self.assertFalse(token_only[0]["auth_evidence"])
            self.assertEqual(token_only[0]["status"], "POTENTIAL")

    def test_taint_mode_supports_cross_function_and_conservative_branch_flows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "flow.php").write_text(
                "<?php\n"
                "function relay($value) { return $value; }\n"
                "function endpoint($condition) {\n"
                "  if ($condition) { $value = $_GET['x']; }\n"
                "  else { $value = 'constant'; }\n"
                "  $output = relay($value);\n"
                "  $wpdb->query($output);\n"
                "}\n",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

            self.assertTrue(result.complete, result.diagnostics)
            self.assertEqual(len(result.findings), 1)
            finding = result.findings[0]
            self.assertEqual(finding["status"], "POTENTIAL")
            self.assertTrue(any(step["kind"] == "parameter" for step in finding["trace"]))
            self.assertTrue(any(step["kind"] == "return" for step in finding["trace"]))
            self.assertEqual(finding["source"]["line"], 4)

    def test_cli_accepts_engine_flag_and_defaults_to_regex(self) -> None:
        with (
            patch("main.load_targets", return_value=["fixture"]),
            patch("main.scan_target", return_value=type("Result", (), {"exit_code": 0})()) as scan_mock,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(["--target", "fixture"]), 0)
            self.assertEqual(scan_mock.call_args.kwargs["engine"], "regex")
            self.assertEqual(main(["--target", "fixture", "--engine=regex"]), 0)
            self.assertEqual(scan_mock.call_args.kwargs["engine"], "regex")
            self.assertEqual(main(["--target", "fixture", "--engine=taint"]), 0)
            self.assertEqual(scan_mock.call_args.kwargs["engine"], "taint")


class CliAndReportTests(unittest.TestCase):
    def test_json_report_contains_review_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            finding = {
                "file": "plugin.php",
                "line": 4,
                "type": "Unauthenticated File Upload",
                "confidence": "LOW",
                "auth_present": False,
                "manual_verification_required": True,
                "evidence": "4: $_FILES",
            }
            report_path = write_json_report(
                "fixture", "wordpress", [finding], Path(temporary_directory)
            )

            record = json.loads(report_path.read_text(encoding="utf-8"))[0]

            self.assertEqual(record["file"], "plugin.php")
            self.assertEqual(record["line"], 4)
            self.assertEqual(record["confidence"], "LOW")
            self.assertFalse(record["auth_present"])
            self.assertTrue(record["manual_verification_required"])

    def test_target_scan_writes_reports_and_history_only_to_injected_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            source.mkdir()
            (source / "plugin.php").write_text("<?php $_FILES['upload'];", encoding="utf-8")
            reports = root / "reports"
            output = io.StringIO()
            with (
                patch("main.get_plugin_local_or_instructions", return_value=source),
                redirect_stdout(output),
            ):
                result = scan_target("fixture", reports_dir=reports)

            self.assertEqual(result.exit_code, 1)
            self.assertTrue((reports / "fixture" / "report_patchstack.md").is_file())
            self.assertTrue((reports / "fixture" / "report_json.json").is_file())
            self.assertTrue((reports / "history.json").is_file())

    def test_dry_run_lists_files_without_scanning_or_writing_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            source.mkdir()
            (source / "plugin.php").write_text("<?php $_FILES['upload'];", encoding="utf-8")
            reports = root / "reports"
            output = io.StringIO()
            with (
                patch("main.get_plugin_local_or_instructions", return_value=source),
                patch("main.scan_plugin") as scan_mock,
                redirect_stdout(output),
            ):
                result = scan_target("fixture", dry_run=True, reports_dir=reports)

            self.assertEqual(result.exit_code, 0)
            self.assertIn("plugin.php", output.getvalue())
            scan_mock.assert_not_called()
            self.assertFalse(reports.exists())

    def test_cli_returns_nonzero_when_target_is_not_configured(self) -> None:
        with patch("main.load_targets", return_value=["configured"]):
            self.assertEqual(main(["--target", "missing"]), 2)

    def test_cli_returns_finding_exit_code(self) -> None:
        with (
            patch("main.load_targets", return_value=["fixture"]),
            patch("main.scan_target", return_value=type("Result", (), {"exit_code": 1})()),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(["--target", "fixture"]), 1)

    def test_cli_platform_override_routes_without_unimplemented_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = io.StringIO()
            with (
                patch("main.load_targets", return_value=["fixture"]),
                patch(
                    "main.get_plugin_local_or_instructions",
                    return_value=Path(temporary_directory),
                ),
                patch("main.scan_plugin") as scan_mock,
                redirect_stdout(output),
            ):
                main(["--target", "fixture", "--platform", "laravel"])

            scan_mock.assert_not_called()
            self.assertIn("[platform] laravel", output.getvalue())
            self.assertIn("No vulnerability scan was performed", output.getvalue())


if __name__ == "__main__":
    unittest.main()