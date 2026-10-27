from __future__ import annotations

import json
import io
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from analyzer.wordpress import scan_plugin
from duplicate_checker import is_duplicate, record_finding
from reporter.patchstack import make_report
from tools.download import download_plugin, get_plugin_local_or_instructions


class ScannerTests(unittest.TestCase):
    def test_detects_patterns_and_returns_review_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "sample.php").write_text(
                "<?php\n"
                "$file = $_FILES['upload'];\n"
                "$wpdb->query($_POST['sql']);\n"
                "if ($_COOKIE['ok'] == true) { return; }\n",
                encoding="utf-8",
            )

            findings = scan_plugin(root)

            self.assertEqual(
                {finding["type"] for finding in findings},
                {
                    "Unauthenticated File Upload",
                    "Unauthenticated SQL Injection",
                    "Auth Bypass",
                },
            )
            self.assertTrue(all("Not generated" in finding["poc"] for finding in findings))

    def test_upload_with_file_level_nonce_check_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "guarded.php").write_text(
                "<?php check_admin_referer('upload'); $file = $_FILES['upload'];",
                encoding="utf-8",
            )

            self.assertEqual(scan_plugin(root), [])

    def test_duplicate_window_uses_local_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            reports_dir = Path(temporary_directory)
            self.assertFalse(is_duplicate("file-manager", "upload.php", 12, reports_dir))
            record_finding("file-manager", "upload.php", 12, reports_dir)
            self.assertTrue(is_duplicate("file-manager", "upload.php", 12, reports_dir))
            self.assertFalse(is_duplicate("file-manager", "upload.php", 13, reports_dir))
            history = json.loads((reports_dir / "history.json").read_text(encoding="utf-8"))
            self.assertEqual(history[0]["plugin_slug"], "file-manager")

    def test_sql_pattern_requires_post_input_in_query_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "unrelated.php").write_text(
                "<?php\n$_POST['name'];\n$wpdb->query('SELECT 1');\n",
                encoding="utf-8",
            )

            self.assertNotIn(
                "Unauthenticated SQL Injection",
                {finding["type"] for finding in scan_plugin(root)},
            )

    def test_cookie_comparison_can_span_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "auth.php").write_text(
                "<?php\nif ($_COOKIE['authorized']\n    == true) { return; }\n",
                encoding="utf-8",
            )

            findings = scan_plugin(root)

            self.assertIn("Auth Bypass", {finding["type"] for finding in findings})

    def test_report_contains_manual_review_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            finding = {
                "type": "Auth Bypass",
                "file": "plugin.php",
                "line": 3,
                "description": "Review cookie authorization.",
                "evidence": "3: if ($cookie == true)",
            }
            report_path = make_report("file-manager", finding, Path(temporary_directory))
            report = report_path.read_text(encoding="utf-8")

            for heading in ("## Description", "## PoC", "## Impact", "## CVSS"):
                self.assertIn(heading, report)
            self.assertIn("Not scored", report)

    def test_archive_extraction_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_dir = root / "targets" / "archives"
            archive_dir.mkdir(parents=True)
            with zipfile.ZipFile(archive_dir / "file-manager.zip", "w") as archive:
                archive.writestr("../outside.php", "<?php")

            with self.assertRaisesRegex(ValueError, "Unsafe path"):
                download_plugin("file-manager", archive_dir)

    def test_local_directory_takes_precedence_over_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            plugins_dir = root / "plugins"
            archives_dir = root / "archives"
            (plugins_dir / "file-manager").mkdir(parents=True)
            archives_dir.mkdir()
            (archives_dir / "file-manager.zip").write_bytes(b"not a zip")

            result = get_plugin_local_or_instructions(
                "file-manager", plugins_dir, archives_dir, root / "tmp"
            )

            self.assertEqual(result, plugins_dir / "file-manager")

    def test_helper_extracts_local_archive_into_slug_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archives_dir = root / "archives"
            archives_dir.mkdir()
            with zipfile.ZipFile(archives_dir / "file-manager.zip", "w") as archive:
                archive.writestr("file-manager/plugin.php", "<?php echo 'local';")

            result = get_plugin_local_or_instructions(
                "file-manager", root / "plugins", archives_dir, root / "tmp" / "plugins"
            )

            self.assertEqual(result, root / "tmp" / "plugins" / "file-manager")
            self.assertTrue((result / "file-manager" / "plugin.php").is_file())

    def test_missing_source_prints_manual_download_instruction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = io.StringIO()
            with redirect_stdout(output):
                result = get_plugin_local_or_instructions(
                    "file-manager", root / "plugins", root / "archives", root / "tmp"
                )

            self.assertIsNone(result)
            self.assertIn(
                "https://downloads.wordpress.org/plugin/file-manager.zip", output.getvalue()
            )
            self.assertIn("targets/archives/file-manager.zip", output.getvalue())


if __name__ == "__main__":
    unittest.main()