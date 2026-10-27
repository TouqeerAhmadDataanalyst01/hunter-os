from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from analyzer.platform import detect_platform
from analyzer.wordpress import scan_plugin
from main import main


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

    def test_auth_check_exactly_50_lines_before_is_likely_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            lines = ["<?php current_user_can('upload');"]
            lines.extend("// filler" for _ in range(49))
            lines.append("$file = $_FILES['upload'];")
            (root / "plugin.php").write_text("\n".join(lines), encoding="utf-8")

            findings = scan_plugin(root)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "LIKELY SAFE - has auth check")

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