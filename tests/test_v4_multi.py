from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from analyzer.platform import detect_platform
from analyzer.taint import TaintSink
from analyzer.wordpress import scan_plugin, scan_plugin_with_taint
from duplicate_checker import is_duplicate, record_finding
from main import main, scan_target
from reporter.json_report import write_json_report


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