from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from analyzer.platform import detect_platform
from analyzer.wordpress import scan_plugin
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