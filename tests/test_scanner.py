from __future__ import annotations

import io
import json
import stat
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from analyzer.wordpress import MAX_SOURCE_BYTES, scan_plugin, scan_plugin_with_summary
from analyzer.php_parser import (
    MAX_NESTED_CALLS,
    OutputStatement,
    parse_php,
    parse_php_file,
)
from analyzer.taint import (
    DEFAULT_SANITIZERS,
    DEFAULT_SOURCES,
    PropagatorSpec,
    SanitizerSpec,
    TaintLimits,
    TaintSink,
    TaintSource,
    analyze_program,
)
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

    def test_upload_with_nonce_check_remains_potential_and_annotated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "guarded.php").write_text(
                "<?php check_admin_referer('upload');\n$file = $_FILES['upload'];",
                encoding="utf-8",
            )

            findings = scan_plugin(root)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "POTENTIAL")
            self.assertTrue(findings[0]["auth_present"])
            self.assertEqual(findings[0]["auth_check"], "check_admin_referer")

    def test_scans_only_root_and_primary_directories_outside_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source_files = {
                "plugin.php": "<?php $file = $_FILES['root'];",
                "includes/handler.php": "<?php $file = $_FILES['includes'];",
                "admin/handler.php": "<?php $file = $_FILES['admin'];",
                "public/handler.php": "<?php $file = $_FILES['public'];",
                "vendor/package/handler.php": "<?php $file = $_FILES['vendor'];",
                "node_modules/package/handler.php": "<?php $file = $_FILES['node'];",
                "tests/helper.php": "<?php $file = $_FILES['tests'];",
                "test/helper.php": "<?php $file = $_FILES['test'];",
                "my-vendor-helper.php": "<?php $file = $_FILES['vendor_name'];",
                "assets/handler.php": "<?php $file = $_FILES['assets'];",
            }
            for relative_name, content in source_files.items():
                source_path = root / relative_name
                source_path.parent.mkdir(parents=True, exist_ok=True)
                source_path.write_text(content, encoding="utf-8")

            findings = scan_plugin(root)

            self.assertEqual(
                {finding["file"] for finding in findings},
                {
                    "plugin.php",
                    "includes/handler.php",
                    "admin/handler.php",
                    "public/handler.php",
                    "my-vendor-helper.php",
                },
            )

    def test_auth_check_beyond_50_lines_does_not_mark_finding_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            lines = ["<?php current_user_can('upload');"]
            lines.extend("// filler" for _ in range(50))
            lines.append("$file = $_FILES['upload'];")
            (root / "plugin.php").write_text("\n".join(lines), encoding="utf-8")

            findings = scan_plugin(root)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "POTENTIAL")
            self.assertFalse(findings[0]["auth_present"])

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

            self.assertIsNotNone(result)
            self.assertTrue(result.is_relative_to(root / "tmp" / "plugins"))
            self.assertTrue((result / "plugin.php").is_file())

    def test_archive_total_expanded_size_and_member_count_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_dir = root / "archives"
            archive_dir.mkdir()
            archive_path = archive_dir / "file-manager.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("one.txt", "1234")
                archive.writestr("two.txt", "5678")

            with patch("tools.download.MAX_TOTAL_EXPANDED_BYTES", 7):
                with self.assertRaisesRegex(ValueError, "expands beyond"):
                    download_plugin("file-manager", archive_dir)
            with patch("tools.download.MAX_ARCHIVE_MEMBERS", 1):
                with self.assertRaisesRegex(ValueError, "members"):
                    download_plugin("file-manager", archive_dir)
            with patch("tools.download.MAX_MEMBER_BYTES", 3):
                with self.assertRaisesRegex(ValueError, "member is too large"):
                    download_plugin("file-manager", archive_dir)

    def test_archive_rejects_windows_traversal_and_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_dir = root / "archives"
            archive_dir.mkdir()
            archive_path = archive_dir / "file-manager.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(r"..\outside.php", "<?php")
            with self.assertRaisesRegex(ValueError, "Unsafe path"):
                download_plugin("file-manager", archive_dir)

            with zipfile.ZipFile(archive_path, "w") as archive:
                link = zipfile.ZipInfo("link.php")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, "outside.php")
            with self.assertRaisesRegex(ValueError, "Symbolic links"):
                download_plugin("file-manager", archive_dir)

    def test_archive_scans_use_isolated_extraction_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_dir = root / "archives"
            archive_dir.mkdir()
            archive_path = archive_dir / "file-manager.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("first.php", "<?php")
            extraction_root = root / "tmp"
            first = get_plugin_local_or_instructions(
                "file-manager", root / "plugins", archive_dir, extraction_root
            )
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("second.php", "<?php")
            second = get_plugin_local_or_instructions(
                "file-manager", root / "plugins", archive_dir, extraction_root
            )

            self.assertNotEqual(first, second)
            self.assertTrue((first / "first.php").is_file())
            self.assertFalse((first / "second.php").exists())
            self.assertTrue((second / "second.php").is_file())

    def test_scan_summary_reports_oversized_unreadable_and_out_of_scope_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "plugin.php").write_text("<?php", encoding="utf-8")
            (root / "large.php").write_bytes(b"x" * (MAX_SOURCE_BYTES + 1))
            unreadable = root / "includes" / "unreadable.php"
            unreadable.parent.mkdir()
            unreadable.write_text("<?php", encoding="utf-8")
            out_of_scope = root / "assets"
            out_of_scope.mkdir()
            (out_of_scope / "ignored.php").write_text("<?php", encoding="utf-8")
            original_read_text = Path.read_text

            def failing_read(path: Path, *args: object, **kwargs: object) -> str:
                if path == unreadable:
                    raise PermissionError("test unreadable source")
                return original_read_text(path, *args, **kwargs)

            with patch.object(Path, "read_text", failing_read):
                summary = scan_plugin_with_summary(root)

            self.assertEqual(summary.scanned_files, 1)
            dispositions = {(entry["path"], entry["reason"]) for entry in summary.skipped}
            self.assertIn(("large.php", "oversized"), dispositions)
            self.assertIn(("includes/unreadable.php", "unreadable"), dispositions)
            self.assertIn(("assets/**", "out of scan scope"), dispositions)

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


class PhpParserTests(unittest.TestCase):
    FIXTURES = Path(__file__).parent / "fixtures" / "php"

    def test_echo_and_print_output_statements_preserve_locations(self) -> None:
        program = parse_php(
            "<?php function output(){ echo $_GET['x'], esc_html($x); print($x); }",
            "output.php",
        )

        self.assertTrue(program.complete, program.diagnostics)
        statements = program.functions[0].body
        self.assertTrue(all(isinstance(item, OutputStatement) for item in statements))
        echo, print_statement = statements
        self.assertEqual(echo.kind, "echo")
        self.assertEqual(len(echo.expressions), 2)
        self.assertEqual(echo.location.line, 1)
        self.assertEqual(print_statement.kind, "print")
        self.assertEqual(len(print_statement.expressions), 1)

    def test_malformed_output_statement_is_not_complete(self) -> None:
        program = parse_php("<?php function output(){ echo $_GET['x'] }")

        self.assertFalse(program.complete)
        self.assertTrue(program.diagnostics)

    def test_supported_subset_tracks_functions_methods_assignments_calls_and_branches(self) -> None:
        program = parse_php_file(self.FIXTURES / "supported.php")

        self.assertTrue(program.complete, program.diagnostics)
        self.assertEqual([function.name for function in program.functions], ["fetch_user"])
        function = program.functions[0]
        self.assertEqual(function.parameters, ("$id",))
        assignment = function.body[0]
        self.assertEqual(assignment.target, "$row")
        self.assertEqual(assignment.value.variables, ("$wpdb", "$id"))
        self.assertEqual(assignment.value.calls[0].name, "$wpdb->get_row")
        self.assertEqual(assignment.value.calls[0].location.line, 3)
        branch = function.body[1]
        self.assertEqual(branch.condition.text, "$id > 0")
        self.assertEqual(branch.then_body[0].value.calls[0].name, "sanitize_text_field")
        self.assertEqual(len(program.classes), 1)
        method = program.classes[0].methods[0]
        self.assertEqual(method.kind, "method")
        self.assertEqual(method.modifiers, ("public",))
        self.assertEqual(method.parameters, ("$request",))
        self.assertEqual(method.body[0].target, "$name")
        self.assertEqual(method.body[0].value.calls[0].name, "$request->get_param")

    def test_malformed_and_unsupported_fixtures_never_claim_complete_parse(self) -> None:
        malformed = parse_php_file(self.FIXTURES / "malformed.php")
        unsupported = parse_php_file(self.FIXTURES / "unsupported.php")
        malformed_assignment = parse_php("<?php $value = ;")
        malformed_expression = parse_php("<?php $value = $other + ;")
        unterminated_string = parse_php("<?php $value = 'unfinished;")

        self.assertFalse(malformed.complete)
        self.assertTrue(any(item.code == "parser_error" for item in malformed.diagnostics))
        self.assertFalse(unsupported.complete)
        self.assertTrue(
            any("foreach" in item.message for item in unsupported.diagnostics)
        )
        self.assertFalse(malformed_assignment.complete)
        self.assertFalse(malformed_expression.complete)
        self.assertFalse(unterminated_string.complete)

    def test_inline_html_and_interpolated_strings_are_explicitly_incomplete(self) -> None:
        inline_html = parse_php("<p>HTML</p><?php $value = 1;")
        self.assertFalse(inline_html.complete)
        self.assertTrue(any(item.code == "inline_html" for item in inline_html.diagnostics))

        interpolated = parse_php('<?php $value = "$name";')
        self.assertFalse(interpolated.complete)
        self.assertTrue(
            any(item.code == "unsupported_interpolation" for item in interpolated.diagnostics)
        )
        embedded_tag = parse_php("<?php $value = '<?php';")
        self.assertTrue(embedded_tag.complete, embedded_tag.diagnostics)

        attribute = parse_php("<?php #[Route] function route() {}")
        self.assertFalse(attribute.complete)
        self.assertTrue(
            any("attributes" in item.message for item in attribute.diagnostics)
        )
        nested_calls = parse_php(
            "<?php consume("
            + "wrap(" * (MAX_NESTED_CALLS + 2)
            + "'value'"
            + ")" * (MAX_NESTED_CALLS + 2)
            + ");"
        )
        self.assertFalse(nested_calls.complete)


class TaintAnalysisTests(unittest.TestCase):
    sources = (TaintSource("$_GET"), TaintSource("$_POST"))
    sinks = (TaintSink("consume", "test"),)

    def analyze(self, source: str, **kwargs: object):
        program = parse_php(source, "taint-fixture.php")
        options: dict[str, object] = {"sources": self.sources, "sinks": self.sinks}
        options.update(kwargs)
        return analyze_program(program, **options)

    def test_tracks_source_through_assignments_calls_and_sink(self) -> None:
        result = self.analyze(
            "<?php\n"
            "$input = $_GET['value'];\n"
            "$copy = normalize($input);\n"
            "consume($copy);\n"
        )

        self.assertTrue(result.complete, result.diagnostics)
        self.assertEqual(len(result.flows), 1)
        flow = result.flows[0]
        self.assertEqual(flow.source.name, "$_GET")
        self.assertEqual(flow.source.location.line, 2)
        self.assertEqual(flow.sink.name, "consume")
        self.assertEqual(flow.sink.location.line, 4)
        self.assertEqual(flow.context, "test")
        self.assertFalse(flow.mitigated)
        self.assertTrue(any(step.kind == "assignment" for step in flow.trace))
        self.assertTrue(any(step.name == "normalize" for step in flow.trace))

    def test_registered_propagator_and_compound_assignment_keep_source_trace(self) -> None:
        result = self.analyze(
            "<?php\n"
            "$input = 'prefix';\n"
            "$input .= $_GET['value'];\n"
            "$output = normalize($input);\n"
            "consume($output);\n",
            propagators=(PropagatorSpec("normalize"),),
        )

        self.assertTrue(result.complete, result.diagnostics)
        self.assertEqual(len(result.flows), 1)
        flow = result.flows[0]
        self.assertEqual(flow.source.location.line, 3)
        self.assertTrue(any(step.kind == "propagator" for step in flow.trace))

    def test_nested_source_and_sanitizer_calls_propagate_to_sink(self) -> None:
        source_result = self.analyze(
            "<?php consume(get_request());",
            sources=(TaintSource("get_request", "call"),),
        )
        sanitized_result = self.analyze(
            "<?php consume(escape_html($_GET['value']));",
            sinks=(TaintSink("consume", "html"),),
            sanitizers=(SanitizerSpec("escape_html", frozenset({"html"})),),
        )

        self.assertEqual(len(source_result.flows), 1)
        self.assertEqual(source_result.flows[0].source.name, "get_request")
        self.assertEqual(len(sanitized_result.flows), 1)
        self.assertTrue(sanitized_result.flows[0].mitigated)

    def test_branches_merge_taint_without_using_nearby_auth_as_protection(self) -> None:
        result = self.analyze(
            "<?php\n"
            "function endpoint($condition) {\n"
            "  if ($condition) { $value = $_POST['value']; }\n"
            "  else { $value = 'constant'; }\n"
            "  // current_user_can('manage_options') is not proof for this path\n"
            "  consume($value);\n"
            "}\n"
        )

        self.assertTrue(result.complete, result.diagnostics)
        self.assertEqual(len(result.flows), 1)
        self.assertEqual(result.flows[0].source.name, "$_POST")
        self.assertEqual(result.flows[0].sink.location.line, 6)
        self.assertFalse(result.flows[0].mitigated)

    def test_tracks_tainted_arguments_and_returns_across_functions(self) -> None:
        result = self.analyze(
            "<?php\n"
            "function relay($value) { return $value; }\n"
            "function endpoint() {\n"
            "  $input = $_GET['value'];\n"
            "  $output = relay($input);\n"
            "  consume($output);\n"
            "}\n"
        )

        self.assertTrue(result.complete, result.diagnostics)
        self.assertEqual(len(result.flows), 1)
        self.assertTrue(any(step.kind == "parameter" for step in result.flows[0].trace))
        self.assertTrue(any(step.kind == "return" for step in result.flows[0].trace))

    def test_sanitizer_evidence_is_context_specific_and_not_discarded(self) -> None:
        source = "<?php $input = $_GET['value']; $safe = escape_html($input); consume($safe);"
        html_result = self.analyze(
            source,
            sinks=(TaintSink("consume", "html"),),
            sanitizers=(SanitizerSpec("escape_html", frozenset({"html"})),),
        )
        sql_result = self.analyze(
            source,
            sinks=(TaintSink("consume", "sql"),),
            sanitizers=(SanitizerSpec("escape_html", frozenset({"html"})),),
        )

        self.assertEqual(len(html_result.flows), 1)
        self.assertTrue(html_result.flows[0].mitigated)
        self.assertEqual(len(html_result.flows[0].sanitizers), 1)
        self.assertEqual(len(sql_result.flows), 1)
        self.assertFalse(sql_result.flows[0].mitigated)
        self.assertEqual(len(sql_result.flows[0].sanitizers), 1)

    def test_clean_input_has_no_flow_and_incomplete_parser_is_not_analyzed(self) -> None:
        clean = self.analyze("<?php consume('constant'); consume('$_GET');")
        malformed = self.analyze("<?php $input = $_GET['value']; consume($input)")

        self.assertTrue(clean.complete)
        self.assertEqual(clean.flows, [])
        self.assertFalse(malformed.complete)
        self.assertEqual(malformed.flows, [])
        self.assertTrue(malformed.diagnostics)

    def test_default_wordpress_registry_keeps_sanitizers_context_limited(self) -> None:
        self.assertIn(TaintSource("$_POST"), DEFAULT_SOURCES)
        self.assertIn(
            SanitizerSpec("sanitize_text_field", frozenset({"input_validation"})),
            DEFAULT_SANITIZERS,
        )
        program = parse_php(
            "<?php $input = $_POST['value']; "
            "$checked = sanitize_text_field($input); "
            "$wpdb->query($checked);"
        )
        result = analyze_program(program)

        self.assertTrue(result.complete, result.diagnostics)
        self.assertEqual(len(result.flows), 1)
        self.assertFalse(result.flows[0].mitigated)
        self.assertEqual(result.flows[0].context, "sql")

    def test_nonce_verification_does_not_mitigate_sensitive_action_context(self) -> None:
        result = self.analyze(
            "<?php perform_action(wp_verify_nonce($_POST['nonce']));",
            sinks=(TaintSink("perform_action", "sensitive_action"),),
        )

        self.assertEqual(len(result.flows), 1)
        self.assertFalse(result.flows[0].mitigated)
        self.assertEqual(
            [step.name for step in result.flows[0].sanitizers], ["wp_verify_nonce"]
        )

    def test_recursion_and_step_limits_mark_analysis_incomplete(self) -> None:
        recursive = self.analyze(
            "<?php\n"
            "function relay($value) { return relay($value); }\n"
            "$input = $_GET['value'];\n"
            "$output = relay($input);\n"
            "consume($output);\n",
            limits=TaintLimits(max_call_depth=2),
        )
        steps = self.analyze(
            "<?php $input = $_GET['value']; $copy = $input; consume($copy);",
            limits=TaintLimits(max_steps=1),
        )

        self.assertFalse(recursive.complete)
        self.assertTrue(recursive.diagnostics)
        self.assertFalse(steps.complete)
        self.assertTrue(steps.diagnostics)

    def test_tainted_value_limit_marks_partial_analysis_incomplete(self) -> None:
        result = self.analyze(
            "<?php $input = combine($_GET['a'], $_POST['b']); consume($input);",
            limits=TaintLimits(max_values_per_variable=1),
        )

        self.assertFalse(result.complete)
        self.assertTrue(any(item.code == "value_limit" for item in result.diagnostics))

    def test_flow_limit_marks_partial_analysis_incomplete(self) -> None:
        result = self.analyze(
            "<?php consume(combine($_GET['a'], $_POST['b']));",
            limits=TaintLimits(max_flows=1),
        )

        self.assertFalse(result.complete)
        self.assertEqual(len(result.flows), 1)
        self.assertTrue(any(item.code == "flow_limit" for item in result.diagnostics))


if __name__ == "__main__":
    unittest.main()