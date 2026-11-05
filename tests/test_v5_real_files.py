from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from analyzer.wordpress import scan_plugin_with_taint
from main import scan_source_path

ROOT = Path(__file__).resolve().parent.parent
REAL_FILES = Path(__file__).resolve().parent / "real_files"


def run_file(engine: str, name: str) -> tuple[int, dict[str, object] | list[object]]:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "main.py"),
            f"--engine={engine}",
            str(REAL_FILES / name),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode not in {0, 1}:
        raise AssertionError(
            f"{engine} scan of {name} failed ({completed.returncode}): "
            f"{completed.stdout}{completed.stderr}"
        )
    return completed.returncode, json.loads(completed.stdout)


def active_findings(report: dict[str, object]) -> list[dict[str, object]]:
    return report["v5_taint_findings"]  # type: ignore[return-value]


class RealFileVerificationTests(unittest.TestCase):
    def assert_v4_findings_match_regex(self, name: str) -> dict[str, object]:
        _, taint_report = run_file("taint", name)
        _, regex_report = run_file("regex", name)
        self.assertIsInstance(regex_report, list)
        self.assertEqual(taint_report["findings"], regex_report)
        return taint_report

    def assert_v5_finding_contract(self, report: dict[str, object]) -> None:
        audit_findings = [
            item["finding"]
            for item in report["v5_audit"]
            if isinstance(item, dict) and isinstance(item.get("finding"), dict)
        ]
        for finding in [*active_findings(report), *audit_findings]:
            with self.subTest(finding=finding):
                self.assertIn(finding["confidence"], {"high", "medium", "low"})
                self.assertTrue(finding["confidence_reason"])
                self.assertTrue(finding["trace"])
                self.assertTrue(all(step.get("line") for step in finding["trace"]))
                self.assertIsInstance(finding["sanitizer_evidence"], list)
                self.assertIsInstance(finding["auth_evidence"], list)
                self.assertIn(
                    finding["entry_point"],
                    {"wp_ajax_", "shortcode", "rest", "direct", "unknown"},
                )
                self.assertTrue(finding["note"])

    def test_xss_real_files_and_regex_compatibility(self) -> None:
        vulnerable = self.assert_v4_findings_match_regex("vuln_xss.php")
        self.assert_v5_finding_contract(vulnerable)
        xss = [
            finding for finding in active_findings(vulnerable)
            if finding["type"] == "Cross-Site Scripting (XSS)"
        ]
        self.assertEqual(len(xss), 1)
        self.assertEqual(xss[0]["confidence"], "high")
        trace = xss[0]["trace"]
        self.assertEqual(
            [step["name"] for step in trace],
            ["$_GET", "$id", "echo"],
        )

        safe = self.assert_v4_findings_match_regex("safe_xss.php")
        self.assert_v5_finding_contract(safe)
        self.assertFalse(active_findings(safe))
        self.assertTrue(any(
            item["finding"]["function"] == "safe"
            and item["finding"]["type"] == "Cross-Site Scripting (XSS)"
            for item in safe["v5_audit"]
        ))

    def test_sqli_real_files_and_regex_compatibility(self) -> None:
        vulnerable = self.assert_v4_findings_match_regex("vuln_sqli.php")
        self.assert_v5_finding_contract(vulnerable)
        sqli = [
            finding for finding in active_findings(vulnerable)
            if finding["type"] == "SQL Injection"
        ]
        self.assertEqual(len(sqli), 1)
        trace_names = [step["name"] for step in sqli[0]["trace"]]
        self.assertEqual(trace_names, ["$_GET", "$id", "$wpdb->query"])
        self.assertFalse(any(
            item["type"] == "Incomplete taint analysis"
            for item in active_findings(vulnerable)
        ))

        safe = self.assert_v4_findings_match_regex("safe_sqli.php")
        self.assert_v5_finding_contract(safe)
        self.assertFalse(active_findings(safe))
        self.assertTrue(any(
            item["reason"] == "effective sanitizer"
            and item["finding"]["type"] == "SQL Injection"
            for item in safe["v5_audit"]
        ))

    def test_ajax_real_files_and_regex_compatibility(self) -> None:
        vulnerable = self.assert_v4_findings_match_regex("vuln_ajax.php")
        self.assert_v5_finding_contract(vulnerable)
        ajax_findings = [
            finding for finding in active_findings(vulnerable)
            if finding["type"] == "Unauthenticated WordPress AJAX Action"
        ]
        self.assertEqual(len(ajax_findings), 1)
        self.assertTrue(
            "nonce is not auth" in ajax_findings[0]["note"]
            or "missing current_user_can" in ajax_findings[0]["note"]
        )
        self.assertEqual(len(active_findings(vulnerable)), 1)

        safe = self.assert_v4_findings_match_regex("safe_ajax.php")
        self.assert_v5_finding_contract(safe)
        self.assertFalse(active_findings(safe))
        self.assertTrue(any(
            item["finding"]["type"] == "Unauthenticated WordPress AJAX Action"
            for item in safe["v5_audit"]
        ))

    def test_rest_and_traversal_real_files_and_regex_compatibility(self) -> None:
        rest = self.assert_v4_findings_match_regex("vuln_rest.php")
        self.assert_v5_finding_contract(rest)
        rest_types = {finding["type"] for finding in active_findings(rest)}
        self.assertIn("WordPress REST Route Authorization", rest_types)
        self.assertIn("Cross-Site Scripting (XSS)", rest_types)

        traversal = self.assert_v4_findings_match_regex("vuln_traversal.php")
        self.assert_v5_finding_contract(traversal)
        traversal_findings = [
            finding for finding in active_findings(traversal)
            if finding["type"] == "Directory Traversal / Local File Inclusion"
        ]
        self.assertEqual(len(traversal_findings), 1)
        self.assertEqual(traversal_findings[0]["sink"]["name"], "include")
        self.assertFalse(any(
            finding["type"] == "Incomplete taint analysis"
            for finding in active_findings(traversal)
        ))

    def test_real_plugin_folder_scan_reports_vulnerable_and_safe_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            reports = Path(temporary_directory) / "reports"
            result = scan_source_path(
                REAL_FILES / "test-plugin",
                engine="taint",
                reports_dir=reports,
            )
            json_report = json.loads(
                (reports / "test-plugin" / "report_json.json").read_text(
                    encoding="utf-8"
                )
            )
            markdown = (
                reports / "test-plugin" / "report_patchstack.md"
            ).read_text(encoding="utf-8")

        self.assertEqual(result.exit_code, 1)
        active = active_findings(json_report)
        self.assertEqual(
            {finding["type"] for finding in active},
            {"Cross-Site Scripting (XSS)", "SQL Injection"},
        )
        self.assertEqual(len(json_report["v5_audit"]), 1)
        self.assertIn("V5 Taint Analysis", markdown)
        self.assertIn("Source-to-sink trace", markdown)
        self.assertIn("V5 Audit (`v5_audit`)", markdown)

    def test_fifty_file_folder_scan_finishes_within_thirty_seconds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "fifty-plugin"
            source.mkdir()
            for index in range(50):
                (source / f"file-{index}.php").write_text(
                    "<?php echo $_GET['value'];",
                    encoding="utf-8",
                )

            started = time.perf_counter()
            result = scan_source_path(
                source,
                engine="taint",
                reports_dir=root / "reports",
            )
            elapsed = time.perf_counter() - started

        self.assertEqual(result.exit_code, 1)
        self.assertLess(elapsed, 30)

    def test_nonce_is_not_auth_and_blog_capability_is_recognized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "nonce.php").write_text(
                "<?php add_action('wp_ajax_nopriv_delete', 'del'); "
                "function del(){ check_ajax_referer('delete'); "
                "wp_delete_post($_POST['id']); }",
                encoding="utf-8",
            )
            (root / "guarded.php").write_text(
                "<?php function guarded(){ "
                "if(!current_user_can_for_blog(1, 'delete_posts')) return; "
                "wp_delete_post($_POST['id']); }",
                encoding="utf-8",
            )

            result = scan_plugin_with_taint(root)

        nonce_findings = [
            item for item in result.findings
            if item["type"] == "Unauthenticated WordPress AJAX Action"
            and item["file"] == "nonce.php"
        ]
        guarded_findings = [
            item for item in result.findings
            if item["file"] == "guarded.php"
        ]
        self.assertEqual(len(nonce_findings), 1)
        self.assertEqual(nonce_findings[0]["note"], "nonce is not auth")
        self.assertTrue(any(
            item["finding"]["file"] == "guarded.php"
            for item in result.audit
        ))


if __name__ == "__main__":
    unittest.main()
