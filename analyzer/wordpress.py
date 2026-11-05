"""Conservative, regex-based heuristics for local WordPress PHP source."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from analyzer.php_parser import (
    Assignment,
    Call,
    CallStatement,
    ControlStatement,
    Expression,
    FunctionDef,
    IfStatement,
    OutputStatement,
    Program,
    ReturnStatement,
    SourceLocation,
    Statement,
    parse_php_file,
)
from analyzer.detectors import detect_hardcoded_secrets
from analyzer.frameworks.wordpress import (
    WordPressEntryPoint,
    discover_wordpress_entrypoints,
    resolve_entrypoint_callbacks,
)
from analyzer.taint import (
    DEFAULT_SOURCES,
    DEFAULT_SANITIZERS,
    TaintAnalysisResult,
    TaintFlow,
    TaintLimits,
    TaintSource,
    analyze_program,
)


IGNORE_DIRS = {"vendor", "node_modules", "dist", ".git", "__pycache__", "tests", "test"}
PRIMARY_DIRECTORIES = {"includes", "admin", "public"}
AUTH_CHECK_PATTERN = re.compile(
    r"current_user_can|check_ajax_referer|check_admin_referer|"
    r"wp_verify_nonce|is_user_logged_in|permission_callback",
    re.IGNORECASE,
)
MAX_SOURCE_BYTES = 2_000_000
MAX_FILE_ANALYSIS_SECONDS = 5.0
MAX_CALL_DEPTH = 3
NONCE_CALLS = {
    "wp_nonce",
    "wp_create_nonce",
    "wp_nonce_field",
    "wp_nonce_url",
    "check_ajax_referer",
    "check_admin_referer",
    "wp_verify_nonce",
}
AUTH_CALLS = {
    "current_user_can",
    "current_user_can_for_blog",
    "user_can",
}


@dataclass
class ScanSummary:
    findings: list[dict[str, object]] = field(default_factory=list)
    scanned_files: int = 0
    skipped: list[dict[str, str]] = field(default_factory=list)


@dataclass
class TaintScanSummary:
    findings: list[dict[str, object]] = field(default_factory=list)
    audit: list[dict[str, object]] = field(default_factory=list)
    recognized_audits: list[dict[str, object]] = field(default_factory=list)
    diagnostics: list[dict[str, object]] = field(default_factory=list)
    query_build_available: bool = False
    complete: bool = True


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _context(text: str, line: int, radius: int = 2) -> str:
    lines = text.splitlines()
    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    return "\n".join(
        f"{index + 1}: {lines[index]}" for index in range(start, end)
    )


def _is_in_scan_scope(path: Path, root: Path) -> bool:
    relative_path = path.relative_to(root)
    if any(part.lower() in IGNORE_DIRS for part in relative_path.parts[:-1]):
        return False
    if path.suffix.lower() != ".php":
        return False
    return len(relative_path.parts) == 1 or relative_path.parts[0].lower() in PRIMARY_DIRECTORIES


def _auth_check_before(text: str, offset: int) -> str | None:
    line_start = text.rfind("\n", 0, offset) + 1
    previous_lines = text[:line_start].splitlines()[-50:]
    match = AUTH_CHECK_PATTERN.search("\n".join(previous_lines))
    return match.group(0) if match else None


def _inspect_file(
    path: Path, root: Path
) -> tuple[list[dict[str, object]], str | None]:
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            return [], "oversized"
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], "unreadable"

    relative_file = path.relative_to(root).as_posix()
    findings: list[dict[str, object]] = []

    checks = (
        (
            "Unauthenticated File Upload",
            re.compile(r"\$_FILES\b", re.IGNORECASE),
            "File upload input is present, but no capability or nonce check was found in this file.",
        ),
        (
            "Unauthenticated SQL Injection",
            re.compile(
                r"\$wpdb\s*->\s*query\s*\([^;]{0,500}?\$_POST\b",
                re.IGNORECASE,
            ),
            "A database query call and POST input occur in this file; verify that values are validated and parameterized.",
        ),
        (
            "Auth Bypass",
            re.compile(
                r"\$_COOKIE\b[\s\S]{0,300}?(?:==\s*true|true\s*==)", re.IGNORECASE
            ),
            "Cookie input and a comparison with true occur in this file; review the authorization logic.",
        ),
    )

    for finding_type, primary_pattern, description in checks:
        match = primary_pattern.search(text)
        if not match:
            continue
        line = _line_for(text, match.start())
        auth_check = _auth_check_before(text, match.start())
        findings.append(
            {
                "file": relative_file,
                "line": line,
                "type": finding_type,
                "status": "POTENTIAL",
                "confidence": "LOW",
                "auth_present": auth_check is not None,
                "auth_check": auth_check,
                "manual_verification_required": True,
                "description": description,
                "evidence": _context(text, line),
                "poc": "Not generated. Review and validate only in an authorized local test environment.",
            }
        )

    return findings, None


def scan_plugin(path: str | Path) -> list[dict[str, object]]:
    """Scan a local plugin directory and return heuristic source findings.

    The checks are intentionally limited to source inspection: they make no
    network requests and do not claim that a match is an exploitable bug.
    """
    return scan_plugin_with_summary(path).findings


def scan_plugin_with_summary(
    path: str | Path, *, max_files: int | None = None
) -> ScanSummary:
    """Run the existing heuristics and return visible file dispositions."""
    if max_files is not None and max_files < 1:
        raise ValueError("File limit must be positive")
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Plugin source directory not found: {root}")

    summary = ScanSummary()
    walk_errors: list[OSError] = []

    def record_walk_error(error: OSError) -> None:
        walk_errors.append(error)

    candidates: list[Path] = []
    file_limit_reached = False
    for current, directories, filenames in os.walk(
        root, topdown=True, followlinks=False, onerror=record_walk_error
    ):
        current_path = Path(current)
        retained_directories: list[str] = []
        for directory in sorted(directories):
            directory_path = current_path / directory
            relative = directory_path.relative_to(root).as_posix()
            if directory_path.is_symlink():
                summary.skipped.append(
                    {"path": relative, "reason": "symbolic-link directory"}
                )
            elif directory.lower() in IGNORE_DIRS:
                summary.skipped.append(
                    {"path": f"{relative}/**", "reason": "out of scan scope"}
                )
            elif current_path == root and directory.lower() not in PRIMARY_DIRECTORIES:
                summary.skipped.append(
                    {"path": f"{relative}/**", "reason": "out of scan scope"}
                )
            else:
                retained_directories.append(directory)
        directories[:] = retained_directories

        for filename in sorted(filenames):
            source_file = current_path / filename
            relative = source_file.relative_to(root).as_posix()
            if source_file.is_symlink():
                summary.skipped.append(
                    {"path": relative, "reason": "symbolic link"}
                )
            elif _is_in_scan_scope(source_file, root):
                candidates.append(source_file)
                if max_files is not None and len(candidates) > max_files:
                    file_limit_reached = True
                    directories[:] = []
                    break
            else:
                summary.skipped.append(
                    {"path": relative, "reason": "out of scan scope"}
                )
        if file_limit_reached:
            break

    for error in walk_errors:
        try:
            relative = Path(error.filename or root).relative_to(root).as_posix()
        except ValueError:
            relative = str(error.filename or root)
        summary.skipped.append(
            {"path": relative, "reason": "unreadable directory"}
        )

    candidates.sort()
    if file_limit_reached:
        summary.skipped.append(
            {"path": "<remaining PHP files>", "reason": "file-count limit"}
        )
    if max_files is not None and len(candidates) > max_files:
        candidates = candidates[:max_files]
    for source_file in candidates:
        findings, skip_reason = _inspect_file(source_file, root)
        if skip_reason is not None:
            summary.skipped.append(
                {
                    "path": source_file.relative_to(root).as_posix(),
                    "reason": skip_reason,
                }
            )
            continue
        summary.scanned_files += 1
        summary.findings.extend(findings)
    return summary


def _statement_expressions(
    statements: tuple[Statement, ...] | list[Statement],
) -> list[Expression]:
    expressions: list[Expression] = []
    for statement in statements:
        if isinstance(statement, Assignment):
            expressions.append(statement.value)
        elif isinstance(statement, CallStatement):
            expressions.append(statement.expression)
        elif isinstance(statement, OutputStatement):
            expressions.extend(statement.expressions)
        elif isinstance(statement, ReturnStatement) and statement.value is not None:
            expressions.append(statement.value)
        elif isinstance(statement, IfStatement):
            expressions.append(statement.condition)
            expressions.extend(_statement_expressions(statement.then_body))
            expressions.extend(_statement_expressions(statement.else_body))
    return expressions


def _scope_calls(statements: tuple[Statement, ...] | list[Statement]) -> list[Call]:
    return [
        call
        for expression in _statement_expressions(statements)
        for call in expression.calls
    ]


def _contains_call_at(
    statements: tuple[Statement, ...] | list[Statement], location: SourceLocation
) -> bool:
    return any(
        call.location.file == location.file
        and call.location.offset == location.offset
        for call in _scope_calls(statements)
    )


def _is_terminating_body(statements: tuple[Statement, ...]) -> bool:
    if not statements:
        return False
    last = statements[-1]
    if isinstance(last, ReturnStatement):
        return True
    if isinstance(last, CallStatement):
        return any(
            call.name.rsplit("->", 1)[-1].rsplit("::", 1)[-1].casefold()
            in {"exit", "die"}
            for call in last.expression.calls
        )
    return False


def _condition_auth_call(statement: IfStatement) -> tuple[Call, bool] | None:
    calls = [
        call
        for call in statement.condition.calls
        if call.name.rsplit("->", 1)[-1].rsplit("::", 1)[-1].casefold()
        in AUTH_CALLS
    ]
    if len(calls) != 1 or len(statement.condition.calls) != 1:
        return None
    call = calls[0]
    condition = statement.condition.text.strip()
    negated = condition.startswith("!")
    guarded_expression = condition[1:].strip() if negated else condition
    if re.fullmatch(re.escape(call.name) + r"\s*\(.*\)", guarded_expression, re.DOTALL) is None:
        return None
    return call, negated


def _guard_evidence_in_scope(
    statements: tuple[Statement, ...],
    sink_location: SourceLocation,
    scope_name: str,
    relative_file: str,
) -> list[dict[str, object]]:
    for index, statement in enumerate(statements):
        if not isinstance(statement, IfStatement):
            continue
        auth_condition = _condition_auth_call(statement)
        if auth_condition is not None:
            call, negated = auth_condition
            if call.location.offset < sink_location.offset:
                guarded_body = statement.else_body if negated else statement.then_body
                if _contains_call_at(guarded_body, sink_location):
                    return [
                        {
                            "name": call.name,
                            "file": relative_file,
                            "line": call.location.line,
                            "scope": scope_name,
                            "proof": "sink is inside the permitted conditional branch",
                        }
                    ]
                if (
                    negated
                    and _is_terminating_body(statement.then_body)
                    and any(
                        _contains_call_at((later,), sink_location)
                        for later in statements[index + 1 :]
                    )
                ):
                    return [
                        {
                            "name": call.name,
                            "file": relative_file,
                            "line": call.location.line,
                            "scope": scope_name,
                            "proof": "denied conditional branch terminates before the sink",
                        }
                    ]
        nested_evidence = _guard_evidence_in_scope(
            statement.then_body,
            sink_location,
            scope_name,
            relative_file,
        )
        if nested_evidence:
            return nested_evidence
        nested_evidence = _guard_evidence_in_scope(
            statement.else_body,
            sink_location,
            scope_name,
            relative_file,
        )
        if nested_evidence:
            return nested_evidence
    return []


def _auth_evidence_for_flow(
    program: Program,
    flow: TaintFlow,
    relative_file: str,
    framework_auth: dict[int, list[dict[str, object]]] | None = None,
) -> list[dict[str, object]]:
    scopes: list[
        tuple[str, tuple[Statement, ...], FunctionDef | None]
    ] = [
        ("<top-level>", tuple(program.statements), None)
    ]
    functions: list[FunctionDef] = list(program.functions)
    for class_def in program.classes:
        functions.extend(class_def.methods)
    for function in functions:
        scopes.append(
            (_callback_scope_name(function), tuple(function.body), function)
        )

    for scope_name, statements, function in scopes:
        calls = _scope_calls(statements)
        sink_in_scope = any(
            call.location.file == flow.sink.location.file
            and call.location.offset == flow.sink.location.offset
            for call in calls
        )
        if not sink_in_scope:
            continue
        evidence = _guard_evidence_in_scope(
            statements, flow.sink.location, scope_name, relative_file
        )
        if evidence:
            return evidence
        if function is not None and framework_auth is not None:
            return framework_auth.get(id(function), [])
    return []


def _location_record(
    location: SourceLocation, relative_file: str
) -> dict[str, object]:
    return {
        "file": relative_file,
        "line": location.line,
        "column": location.column,
    }


def _finding_from_flow(
    flow: TaintFlow,
    auth_evidence: list[dict[str, object]],
    relative_file: str,
    program: Program,
) -> dict[str, object]:
    source = {
        "name": flow.source.name,
        **_location_record(flow.source.location, relative_file),
    }
    sink = {
        "name": flow.sink.name,
        **_location_record(flow.sink.location, relative_file),
    }
    trace = [
        {
            "kind": "source",
            "name": flow.source.name,
            **_location_record(flow.source.location, relative_file),
        }
    ]
    trace.extend(
        {
            "kind": step.kind,
            "name": step.name,
            **_location_record(step.location, relative_file),
        }
        for step in flow.trace
    )
    sanitizer_evidence = [
        {
            "name": step.name,
            **_location_record(step.location, relative_file),
            "effective_contexts": sorted(
                next(
                    (
                        sanitizer.contexts
                        for sanitizer in DEFAULT_SANITIZERS
                        if sanitizer.name.casefold() == step.name.casefold()
                    ),
                    frozenset(),
                )
            ),
            "effective": flow.context
            in next(
                (
                    sanitizer.contexts
                    for sanitizer in DEFAULT_SANITIZERS
                    if sanitizer.name.casefold() == step.name.casefold()
                ),
                frozenset(),
            ),
        }
        for step in flow.sanitizers
    ]
    categories = {
        "html": "Cross-Site Scripting (XSS)",
        "sql": "SQL Injection",
        "upload": "Unsafe File Upload",
        "file_path": "Directory Traversal / Local File Inclusion",
        "command": "Command Injection",
        "network_url": "Server-Side Request Forgery",
        "sensitive_action": "Sensitive State-Changing Action",
    }
    finding: dict[str, object] = {
        "file": relative_file,
        "line": flow.sink.location.line,
        "type": categories.get(
            flow.context, f"Tainted data reaches {flow.context} sink {flow.sink.name}"
        ),
        "status": "POTENTIAL",
        "confidence": (
            "high"
            if flow.context == "html"
            and not flow.sanitizers
            and bool(flow.trace)
            and flow.trace[-1].kind == "sink"
            and all(step.kind == "assignment" for step in flow.trace[:-1])
            else "medium"
        ),
        "confidence_reason": (
            "Direct unescaped request data reaches HTML output through assignments."
            if flow.context == "html"
            and not flow.sanitizers
            and bool(flow.trace)
            and flow.trace[-1].kind == "sink"
            and all(step.kind == "assignment" for step in flow.trace[:-1])
            else "A bounded source-to-sink path was observed; exploitability needs manual review."
        ),
        "context": flow.context,
        "function": _function_name_for_location(program, flow.sink.location),
        "source": source,
        "sink": sink,
        "trace": trace,
        "sanitizer_evidence": sanitizer_evidence,
        "auth_evidence": auth_evidence,
        "note": "Source-to-sink evidence requires manual review; authorization is not inferred from nearby tokens.",
    }
    return finding


def _function_name_for_location(
    program: Program, location: SourceLocation
) -> str | None:
    functions = list(program.functions)
    for class_def in program.classes:
        functions.extend(class_def.methods)
    for function in functions:
        body = tuple(function.body)
        if _contains_call_at(body, location) or any(
            isinstance(statement, OutputStatement)
            and statement.location.file == location.file
            and statement.location.offset == location.offset
            for statement in _walk_statements(body)
        ):
            return (
                f"{function.class_name}::{function.name}"
                if function.class_name
                else function.name
            )
    return None


def _walk_statements(
    statements: tuple[Statement, ...] | list[Statement],
) -> list[Statement]:
    result: list[Statement] = []
    for statement in statements:
        result.append(statement)
        if isinstance(statement, IfStatement):
            result.extend(_walk_statements(statement.then_body))
            result.extend(_walk_statements(statement.else_body))
        elif isinstance(statement, ControlStatement):
            result.extend(_walk_statements(statement.body))
            for _, branch_body in statement.branches:
                result.extend(_walk_statements(branch_body))
    return result


def _database_column_allowlist_methods(
    program: Program,
) -> set[tuple[str | None, str]]:
    methods = set()
    for function in _program_functions(program):
        statements = _walk_statements(function.body)
        whitelist_variables = {
            statement.target
            for statement in statements
            if isinstance(statement, Assignment)
            and any(
                call.name.casefold().endswith("->get_col")
                and any(
                    "show columns" in argument.casefold()
                    for argument in call.arguments
                )
                for call in statement.value.calls
            )
        }
        for statement in statements:
            if not isinstance(statement, IfStatement):
                continue
            condition = statement.condition
            if not re.search(r"!==\s*false\b", condition.text, re.IGNORECASE):
                continue
            array_search = next(
                (
                    call
                    for call in condition.calls
                    if call.name.casefold() == "array_search"
                    and len(call.arguments) >= 2
                ),
                None,
            )
            if array_search is None:
                continue
            candidate_match = re.fullmatch(
                r"\s*(\$[A-Za-z_][A-Za-z0-9_]*)\s*",
                array_search.arguments[0],
            )
            if candidate_match is None:
                continue
            candidate = candidate_match.group(1)
            whitelist_argument = re.fullmatch(
                r"\s*(\$[A-Za-z_][A-Za-z0-9_]*)\s*",
                array_search.arguments[1],
            )
            if (
                whitelist_argument is None
                or whitelist_argument.group(1) not in whitelist_variables
            ):
                continue
            append_targets = {
                item.target[:-2]
                for item in _walk_statements(statement.then_body)
                if isinstance(item, Assignment)
                and re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*\[\]", item.target)
                and candidate in item.value.variables
            }
            returned_arrays = {
                item.value.text.strip()
                for item in statements
                if isinstance(item, ReturnStatement) and item.value is not None
            }
            if append_targets & returned_arrays:
                methods.add(
                    (
                        function.class_name.casefold()
                        if function.class_name
                        else None,
                        function.name.casefold(),
                    )
                )
                break
    return methods


def _is_allowlist_method_call(
    call_name: str,
    function: FunctionDef,
    safe_methods: set[tuple[str | None, str]],
) -> bool:
    method_name = call_name.rsplit("->", 1)[-1].casefold()
    if function.class_name:
        return (
            call_name.casefold() == f"$this->{method_name}"
            and (function.class_name.casefold(), method_name) in safe_methods
        )
    return (
        "->" not in call_name
        and call_name.casefold() == method_name
        and (None, method_name) in safe_methods
    )


def _allowlisted_query_build_audits(
    program: Program, relative_file: str
) -> list[dict[str, object]]:
    safe_methods = _database_column_allowlist_methods(program)
    if not safe_methods:
        return []

    for function in _program_functions(program):
        statements = sorted(
            _walk_statements(function.body),
            key=lambda statement: statement.location.offset,
        )
        tainted: dict[str, tuple[str, SourceLocation]] = {}
        allowlisted: dict[str, tuple[str, SourceLocation, SourceLocation]] = {}
        query_variables: set[str] = set()
        query_fields: dict[str, tuple[str, SourceLocation]] = {}
        built_queries: dict[str, tuple[str, SourceLocation]] = {}
        source_names = {
            source.name.casefold()
            for source in DEFAULT_SOURCES
            if source.kind == "variable"
        }

        for statement in statements:
            if isinstance(statement, Assignment):
                value = statement.value
                target = statement.target
                if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", target):
                    source_data = next(
                        (
                            (
                                value.variables[index],
                                value.variable_locations[index]
                                if index < len(value.variable_locations)
                                else statement.location,
                            )
                            for index, name in enumerate(value.variables)
                            if name.casefold() in source_names
                        ),
                        None,
                    )
                    inherited = next(
                        (tainted[name] for name in value.variables if name in tainted),
                        None,
                    )
                    if source_data or inherited:
                        tainted[target] = source_data or inherited

                    sanitizer_call = next(
                        (
                            call
                            for call in value.calls
                            if _is_allowlist_method_call(
                                call.name, function, safe_methods
                            )
                        ),
                        None,
                    )
                    arguments = (
                        tuple(
                            variable
                            for group in sanitizer_call.argument_variables
                            for variable in group
                        )
                        if sanitizer_call
                        else ()
                    )
                    tainted_argument = next(
                        (tainted[name] for name in arguments if name in tainted),
                        None,
                    )
                    if sanitizer_call and tainted_argument:
                        allowlisted[target] = (
                            tainted_argument[0],
                            tainted_argument[1],
                            sanitizer_call.location,
                        )

                    if re.search(r"\bnew\s+\\?Query\s*\(", value.text, re.IGNORECASE):
                        query_variables.add(target)

                    build_call = next(
                        (
                            call
                            for call in value.calls
                            if call.name.casefold().endswith("->build")
                            and not call.arguments
                        ),
                        None,
                    )
                    if build_call is not None:
                        receiver_match = re.match(
                            r"(\$[A-Za-z_][A-Za-z0-9_]*)->build$",
                            build_call.name,
                            re.IGNORECASE,
                        )
                        if (
                            receiver_match is not None
                            and receiver_match.group(1) in query_variables
                            and receiver_match.group(1) in query_fields
                        ):
                            built_queries[target] = (
                                receiver_match.group(1),
                                build_call.location,
                            )
                else:
                    property_match = re.fullmatch(
                        r"(\$[A-Za-z_][A-Za-z0-9_]*)->fields",
                        statement.target,
                        re.IGNORECASE,
                    )
                    safe_variable = next(
                        (
                            variable
                            for variable in value.variables
                            if variable in allowlisted
                        ),
                        None,
                    )
                    if (
                        property_match is not None
                        and property_match.group(1) in query_variables
                        and safe_variable is not None
                    ):
                        query_fields[property_match.group(1)] = (
                            safe_variable,
                            statement.location,
                        )

            expressions = (
                [statement.value]
                if isinstance(statement, Assignment)
                else [statement.expression]
                if isinstance(statement, CallStatement)
                else [statement.condition]
                if isinstance(statement, IfStatement)
                else [statement.value]
                if isinstance(statement, ReturnStatement) and statement.value
                else []
            )
            for expression in expressions:
                for call in expression.calls:
                    if call.name.casefold() not in {
                        "$wpdb->get_results",
                        "$wpdb->get_row",
                        "$wpdb->get_var",
                    }:
                        continue
                    for arguments in call.argument_variables:
                        built = next(
                            (built_queries[name] for name in arguments if name in built_queries),
                            None,
                        )
                        if built is None:
                            continue
                        query_variable, build_location = built
                        safe_variable, property_location = query_fields[query_variable]
                        source_name, source_location, sanitizer_location = (
                            allowlisted[safe_variable]
                        )
                        finding = {
                            "file": relative_file,
                            "line": call.location.line,
                            "type": "SQL Injection",
                            "status": "DOWNGRADED",
                            "confidence": "low",
                            "confidence_reason": (
                                "Downgraded because database column names pass through a "
                                "schema-derived allowlist before reaching the query builder."
                            ),
                            "context": "sql",
                            "function": function.name,
                            "trace": [
                                {
                                    "kind": "source",
                                    "name": source_name,
                                    **_location_record(source_location, relative_file),
                                },
                                {
                                    "kind": "sanitizer",
                                    "name": "database-column allowlist",
                                    **_location_record(sanitizer_location, relative_file),
                                },
                                {
                                    "kind": "object_property",
                                    "name": "->fields",
                                    **_location_record(property_location, relative_file),
                                },
                                {
                                    "kind": "call",
                                    "name": "build",
                                    **_location_record(build_location, relative_file),
                                },
                                {
                                    "kind": "sink",
                                    "name": call.name,
                                    **_location_record(call.location, relative_file),
                                },
                            ],
                            "sanitizer_evidence": [
                                {
                                    "name": "database-column allowlist",
                                    **_location_record(sanitizer_location, relative_file),
                                    "effective_contexts": ["sql"],
                                    "effective": True,
                                }
                            ],
                            "auth_evidence": [],
                            "note": "allowlist fix recognized",
                            "entry_point": "unknown",
                        }
                        return [
                            {
                                "reason": "allowlist fix recognized",
                                "original_confidence": "medium",
                                "original_confidence_reason": (
                                    "Tainted fields pass through a schema-derived allowlist "
                                    "before reaching Query::build()."
                                ),
                                "downgraded_confidence": "low",
                                "finding": finding,
                                "note": "allowlist fix recognized",
                            }
                        ]
    return []


_AJAX_SENSITIVE_CALLS = {
    "update_option",
    "add_option",
    "delete_option",
    "update_user_meta",
    "delete_user_meta",
    "update_post_meta",
    "delete_post_meta",
    "wp_insert_user",
    "wp_delete_user",
    "wp_update_post",
    "wp_delete_post",
    "move_uploaded_file",
    "wp_handle_upload",
    "wp_handle_sideload",
    "unlink",
    "file_put_contents",
    "exec",
    "shell_exec",
    "system",
    "passthru",
}


def _program_functions(program: Program) -> list[FunctionDef]:
    functions = list(program.functions)
    for class_def in program.classes:
        functions.extend(class_def.methods)
    return functions


def _entry_point_record(entry_point: WordPressEntryPoint) -> dict[str, object]:
    record: dict[str, object] = {
        "type": entry_point.kind,
        "name": entry_point.name,
        "callback": entry_point.callback,
        "line": entry_point.location.line,
    }
    if entry_point.route is not None:
        record["route"] = entry_point.route
    if entry_point.permission_callback is not None:
        record["permission_callback"] = entry_point.permission_callback
    return record


def _callback_scope_name(function: FunctionDef) -> str:
    return (
        f"{function.class_name}::{function.name}"
        if function.class_name
        else function.name
    )


def _permission_callback_proof(
    permission_callback: str,
    functions: list[FunctionDef],
    relative_file: str,
) -> list[dict[str, object]]:
    if permission_callback.casefold() == "__return_true":
        return []
    candidates = [
        function
        for function in functions
        if function.name.casefold() == permission_callback.casefold()
        or (
            function.class_name
            and f"{function.class_name}::{function.name}".casefold()
            == permission_callback.casefold()
        )
    ]
    if len(candidates) != 1:
        return []
    function = candidates[0]
    evidence: list[dict[str, object]] = []
    for statement in _walk_statements(tuple(function.body)):
        if not isinstance(statement, ReturnStatement) or statement.value is None:
            continue
        expression = statement.value
        if (
            len(expression.calls) == 1
            and expression.text.strip().casefold().startswith(
                expression.calls[0].name.casefold()
            )
            and expression.calls[0].name.rsplit("->", 1)[-1].rsplit("::", 1)[-1].casefold()
            in AUTH_CALLS
        ):
            call = expression.calls[0]
            evidence.append(
                {
                    "name": call.name,
                    "file": relative_file,
                    "line": call.location.line,
                    "scope": _callback_scope_name(function),
                    "proof": "permission callback directly returns a capability check",
                }
            )
    return evidence


def _framework_authorization_evidence(
    entry_points: list[WordPressEntryPoint],
    functions: list[FunctionDef],
    relative_file: str,
) -> dict[int, list[dict[str, object]]]:
    grouped: dict[int, tuple[FunctionDef, list[WordPressEntryPoint]]] = {}
    for entry_point, function in resolve_entrypoint_callbacks(entry_points, functions):
        grouped.setdefault(id(function), (function, []))[1].append(entry_point)

    evidence_by_function: dict[int, list[dict[str, object]]] = {}
    for function_id, (function, registrations) in grouped.items():
        if not registrations or any(
            registration.kind != "rest" for registration in registrations
        ):
            continue
        proofs = [
            _permission_callback_proof(
                registration.permission_callback, functions, relative_file
            )
            if registration.permission_callback is not None
            else []
            for registration in registrations
        ]
        if all(proofs):
            evidence_by_function[function_id] = [
                item for proof in proofs for item in proof
            ]
    return evidence_by_function


def _wordpress_framework_findings(
    program: Program,
    relative_file: str,
    flows: list[TaintFlow],
    entry_points: list[WordPressEntryPoint] | None = None,
    framework_auth: dict[int, list[dict[str, object]]] | None = None,
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    functions = _program_functions(program)
    if entry_points is None:
        entry_points = discover_wordpress_entrypoints(program)
    resolved = resolve_entrypoint_callbacks(entry_points, functions)

    for entry_point, function in resolved:
        if entry_point.kind == "shortcode":
            continue
        scope_name = _callback_scope_name(function)
        function_body = tuple(function.body)
        function_calls = _scope_calls(function_body)
        if entry_point.kind == "ajax":
            hook = entry_point.name
            sensitive_call = next(
                (
                    call
                    for call in function_calls
                    if call.name.rsplit("->", 1)[-1]
                    .rsplit("::", 1)[-1]
                    .casefold()
                    in _AJAX_SENSITIVE_CALLS
                    or call.name.casefold()
                    in {
                        "$wpdb->query",
                        "$wpdb->get_results",
                        "$wpdb->get_row",
                        "$wpdb->get_var",
                    }
                ),
                None,
            )
            if sensitive_call is None:
                continue
            auth_evidence = _guard_evidence_in_scope(
                function_body,
                sensitive_call.location,
                scope_name,
                relative_file,
            )
            nonce_evidence = [
                {
                    "name": call.name,
                    "file": relative_file,
                    "line": call.location.line,
                    "note": "nonce is not auth",
                }
                for call in function_calls
                if call.name.rsplit("->", 1)[-1].rsplit("::", 1)[-1].casefold()
                in NONCE_CALLS
            ]
            nonce_note = (
                " nonce is not auth"
                if nonce_evidence and not auth_evidence
                else (
                    " missing current_user_can authorization proof."
                    if not auth_evidence
                    else ""
                )
            )
            line = sensitive_call.location.line
            findings.append(
                {
                    "file": relative_file,
                    "line": line,
                    "type": "Unauthenticated WordPress AJAX Action",
                    "status": "POTENTIAL",
                    "confidence": "medium",
                    "context": "ajax_authorization",
                    "function": scope_name,
                    "source": {
                        "name": hook,
                        "file": relative_file,
                        "line": entry_point.location.line,
                    },
                    "sink": {
                        "name": sensitive_call.name,
                        "file": relative_file,
                        "line": line,
                    },
                    "trace": [
                        {
                            "kind": "hook",
                            "name": hook,
                            "file": relative_file,
                            "line": entry_point.location.line,
                        },
                        {
                            "kind": "callback",
                            "name": scope_name,
                            "file": relative_file,
                            "line": function.location.line,
                        },
                        {
                            "kind": "sensitive_operation",
                            "name": sensitive_call.name,
                            "file": relative_file,
                            "line": line,
                        },
                    ],
                    "sanitizer_evidence": [],
                    "auth_evidence": auth_evidence,
                    "nonce_evidence": nonce_evidence,
                    "entry_points": [_entry_point_record(entry_point)],
                    "note": (
                        f"WordPress AJAX callback {hook} reaches a sensitive operation."
                        f"{nonce_note}"
                    ),
                }
            )
            continue

        route_flows = [
            flow
            for flow in flows
            if any(
                call.location.file == flow.sink.location.file
                and call.location.offset == flow.sink.location.offset
                for call in function_calls
            )
            or any(
                isinstance(statement, OutputStatement)
                and statement.location.file == flow.sink.location.file
                and statement.location.offset == flow.sink.location.offset
                for statement in _walk_statements(function_body)
            )
        ]
        if not route_flows:
            continue
        permission_callback = entry_point.permission_callback
        permission_evidence = (
            _permission_callback_proof(
                permission_callback, functions, relative_file
            )
            if permission_callback is not None
            else []
        )
        if permission_callback is not None and (
            permission_callback.casefold() == "__return_true" or not permission_evidence
        ):
            permission_evidence = []
        elif permission_evidence:
            continue
        flow = route_flows[0]
        auth_evidence = _auth_evidence_for_flow(
            program, flow, relative_file, framework_auth
        )
        if auth_evidence:
            continue
        line = flow.sink.location.line
        findings.append(
            {
                "file": relative_file,
                "line": line,
                "type": "WordPress REST Route Authorization",
                "status": "POTENTIAL",
                "confidence": "medium",
                "context": "rest_authorization",
                "function": scope_name,
                "source": {
                    "name": flow.source.name,
                    "file": relative_file,
                    "line": flow.source.location.line,
                },
                "sink": {
                    "name": flow.sink.name,
                    "file": relative_file,
                    "line": line,
                },
                "trace": _finding_from_flow(flow, [], relative_file, program)["trace"],
                "sanitizer_evidence": [],
                "auth_evidence": permission_evidence,
                "entry_point": {
                    **_entry_point_record(entry_point),
                    "route": entry_point.route,
                },
                "note": (
                    "Tainted data reaches a WordPress REST callback sink, but the "
                    "route has no proven permission callback."
                ),
            }
        )
    return findings


def _annotate_entry_points(
    program: Program,
    findings: list[dict[str, object]],
    relative_file: str,
    entry_points: list[WordPressEntryPoint] | None = None,
) -> None:
    resolved = resolve_entrypoint_callbacks(
        entry_points or discover_wordpress_entrypoints(program),
        _program_functions(program),
    )
    records_by_callback: dict[str, list[dict[str, object]]] = {}
    functions_by_callback: dict[str, FunctionDef] = {}
    for entry_point, function in resolved:
        records_by_callback.setdefault(function.name.casefold(), []).append(
            _entry_point_record(entry_point)
        )
        functions_by_callback[function.name.casefold()] = function
    for finding in findings:
        if finding.get("file") != relative_file:
            continue
        function_name = finding.get("function")
        if not isinstance(function_name, str):
            continue
        short_name = function_name.rsplit("::", 1)[-1].casefold()
        entry_points = records_by_callback.get(short_name)
        if entry_points:
            finding["entry_points"] = entry_points
            function = functions_by_callback.get(short_name)
            if function is not None:
                nonce_evidence = [
                    {
                        "name": call.name,
                        "file": relative_file,
                        "line": call.location.line,
                    }
                    for call in _scope_calls(tuple(function.body))
                    if call.name.rsplit("->", 1)[-1]
                    .rsplit("::", 1)[-1]
                    .casefold()
                    in NONCE_CALLS
                ]
                if nonce_evidence:
                    finding["nonce_evidence"] = nonce_evidence
                    if not finding.get("auth_evidence"):
                        finding["note"] = "nonce is not auth"


def _judge_taint_findings(
    findings: list[dict[str, object]],
) -> list[dict[str, object]]:
    audit: list[dict[str, object]] = []
    for index, finding in enumerate(findings):
        sanitizer_evidence = finding["sanitizer_evidence"]
        auth_evidence = finding["auth_evidence"]
        reasons: list[str] = []
        if any(
            isinstance(item, dict) and item.get("effective")
            for item in sanitizer_evidence
        ):
            reasons.append("effective sanitizer")
        if auth_evidence:
            reasons.append("same-function authorization guard before sink")
        if not reasons:
            continue
        original_confidence = finding["confidence"]
        original_confidence_reason = finding["confidence_reason"]
        finding["confidence"] = "low"
        finding["confidence_reason"] = (
            "The judge found context-effective sanitizer or authorization evidence; "
            "the finding is retained for review."
        )
        finding["status"] = "DOWNGRADED"
        audit.append(
            {
                "finding_index": index,
                "reason": "; ".join(reasons),
                "original_confidence": original_confidence,
                "original_confidence_reason": original_confidence_reason,
                "downgraded_confidence": "low",
                "sanitizer_evidence": sanitizer_evidence,
                "auth_evidence": auth_evidence,
                "finding": dict(finding),
                "note": "Judge V2 downgraded but preserved the evidence; this is not proof of safety.",
            }
        )
    return audit


def _ensure_v5_finding_contract(finding: dict[str, object]) -> None:
    confidence = str(finding.get("confidence", "low")).casefold()
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"
    finding["confidence"] = confidence
    finding.setdefault(
        "confidence_reason",
        (
            "Analysis is incomplete; treat this as a warning, not a confirmed issue."
            if finding.get("status") == "INCOMPLETE"
            else "A bounded static-analysis heuristic found a path requiring manual review."
        ),
    )
    trace = finding.get("trace")
    if not isinstance(trace, list):
        finding["trace"] = []
    for step in finding["trace"]:
        if isinstance(step, dict):
            step.setdefault("line", finding.get("line", 1))
    finding.setdefault("sanitizer_evidence", [])
    finding.setdefault("auth_evidence", [])
    finding.setdefault("note", "Manual review is required.")

    entry_point = finding.get("entry_point")
    if isinstance(entry_point, dict):
        finding["entry_point_details"] = entry_point
        entry_kind = entry_point.get("type")
        finding["entry_point"] = (
            "wp_ajax_"
            if entry_kind == "ajax"
            else str(entry_kind)
            if entry_kind in {"rest", "shortcode"}
            else "unknown"
        )
    elif isinstance(entry_point, str) and entry_point in {
        "wp_ajax_",
        "rest",
        "shortcode",
        "direct",
        "unknown",
    }:
        pass
    else:
        entries = finding.get("entry_points")
        entry_types = [
            item.get("type")
            for item in entries
            if isinstance(item, dict)
        ] if isinstance(entries, list) else []
        if "ajax" in entry_types:
            finding["entry_point"] = "wp_ajax_"
        elif "rest" in entry_types:
            finding["entry_point"] = "rest"
        elif "shortcode" in entry_types:
            finding["entry_point"] = "shortcode"
        elif finding.get("function") is None:
            finding["entry_point"] = "direct"
        else:
            finding["entry_point"] = "unknown"

    nonce_evidence = finding.get("nonce_evidence")
    auth_evidence = finding.get("auth_evidence")
    if nonce_evidence and not auth_evidence:
        finding["note"] = "nonce is not auth"


def _finalize_taint_summary(summary: TaintScanSummary) -> None:
    for finding in summary.findings:
        _ensure_v5_finding_contract(finding)
    summary.audit = _judge_taint_findings(summary.findings)
    for finding in summary.findings:
        if finding.get("status") != "INCOMPLETE":
            continue
        summary.audit.append(
            {
                "reason": "analysis incomplete; manual review required",
                "original_confidence": finding["confidence"],
                "original_confidence_reason": finding["confidence_reason"],
                "downgraded_confidence": "low",
                "sanitizer_evidence": finding["sanitizer_evidence"],
                "auth_evidence": finding["auth_evidence"],
                "finding": dict(finding),
                "note": finding["note"],
            }
        )


def _incomplete_finding(
    relative_file: str,
    line: int,
    message: str,
    kind: str,
) -> dict[str, object]:
    return {
        "file": relative_file,
        "line": line,
        "type": "Incomplete taint analysis",
        "status": "INCOMPLETE",
        "confidence": "low",
        "confidence_reason": "Analysis could not fully assess this source file.",
        "trace": [],
        "sanitizer_evidence": [],
        "auth_evidence": [],
        "entry_point": "unknown",
        "note": f"incomplete parse: {message}" if kind == "incomplete_parse" else message,
    }


def scan_plugin_with_taint(
    path: str | Path,
    *,
    timeout_seconds: int | None = None,
    max_files: int | None = None,
) -> TaintScanSummary:
    """Run V4 regex checks and opt-in parser/taint analysis side by side."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Plugin source directory not found: {root}")

    result = TaintScanSummary()
    if max_files is not None and max_files < 1:
        raise ValueError("File limit must be positive")
    if timeout_seconds is not None and timeout_seconds < 1:
        raise ValueError("Timeout must be positive")
    candidates = [
        source_file
        for source_file in list_scan_files(
            root, max_files=max_files + 1 if max_files is not None else None
        )
        if not source_file.is_symlink()
    ]
    over_file_limit = max_files is not None and len(candidates) > max_files
    if over_file_limit:
        candidates = candidates[:max_files]
    started = time.monotonic()
    for index, source_file in enumerate(candidates):
        if timeout_seconds is not None and time.monotonic() - started >= timeout_seconds:
            result.complete = False
            message = f"Taint scan exceeded {timeout_seconds} seconds"
            result.diagnostics.append(
                {
                    "file": "<scan>",
                    "line": 1,
                    "code": "timeout",
                    "message": message,
                }
            )
            result.findings.append(
                _incomplete_finding("<scan>", 1, message, "timeout")
            )
            break
        relative_file = source_file.relative_to(root).as_posix()
        file_started = time.perf_counter()
        _analyze_taint_file(source_file, relative_file, result)
        file_elapsed = time.perf_counter() - file_started
        if file_elapsed >= MAX_FILE_ANALYSIS_SECONDS:
            result.complete = False
            message = (
                f"Per-file taint analysis exceeded {MAX_FILE_ANALYSIS_SECONDS:g} seconds"
            )
            result.diagnostics.append(
                {
                    "file": relative_file,
                    "line": 1,
                    "code": "per_file_timeout",
                    "message": message,
                }
            )
            result.findings.append(
                _incomplete_finding(
                    relative_file,
                    1,
                    message,
                    "per_file_timeout",
                )
            )
        if (
            timeout_seconds is not None
            and time.monotonic() - started >= timeout_seconds
            and index + 1 < len(candidates)
        ):
            result.complete = False
            message = (
                f"Taint scan reached the {timeout_seconds}-second budget; "
                "remaining files were not analyzed"
            )
            result.diagnostics.append(
                {
                    "file": "<scan>",
                    "line": 1,
                    "code": "timeout",
                    "message": message,
                }
            )
            result.findings.append(
                _incomplete_finding("<scan>", 1, message, "timeout")
            )
            break
    if over_file_limit:
        result.complete = False
        message = f"Taint scan exceeded the {max_files}-file analysis limit"
        result.diagnostics.append(
            {
                "file": "<scan>",
                "line": 1,
                "code": "file_count_limit",
                "message": message,
            }
        )
        result.findings.append(
            _incomplete_finding("<scan>", 1, message, "file_count_limit")
        )

    _finalize_taint_summary(result)
    if result.query_build_available:
        result.audit.extend(result.recognized_audits)
    return result


def _analyze_taint_file(
    source_file: Path, relative_file: str, result: TaintScanSummary
) -> None:
    try:
        if source_file.stat().st_size == 0:
            message = "Empty PHP file skipped; no source was analyzed."
            result.complete = False
            result.diagnostics.append(
                {
                    "file": relative_file,
                    "line": 1,
                    "code": "empty_file",
                    "message": message,
                }
            )
            result.findings.append(
                _incomplete_finding(relative_file, 1, message, "empty_file")
            )
            return
    except OSError as error:
        message = f"Could not inspect PHP file: {error}"
        result.complete = False
        result.diagnostics.append(
            {
                "file": relative_file,
                "line": 1,
                "code": "read_error",
                "message": message,
            }
        )
        result.findings.append(
            _incomplete_finding(relative_file, 1, message, "read_error")
        )
        return

    program = parse_php_file(source_file)
    if not program.complete:
        result.complete = False
        result.diagnostics.extend(
            {
                "file": relative_file,
                "line": diagnostic.location.line,
                "code": diagnostic.code,
                "message": diagnostic.message,
            }
            for diagnostic in program.diagnostics
        )
        note = "; ".join(item.message for item in program.diagnostics)
        result.findings.append(
            _incomplete_finding(
                relative_file,
                program.diagnostics[0].location.line
                if program.diagnostics
                else 1,
                note or "PHP parser did not complete",
                "incomplete_parse",
            )
        )
    else:
        if any(
            class_def.name.casefold() == "query"
            and any(
                method.name.casefold() == "build" and not method.parameters
                for method in class_def.methods
            )
            for class_def in program.classes
        ):
            result.query_build_available = True
        result.recognized_audits.extend(
            _allowlisted_query_build_audits(program, relative_file)
        )
        entry_points = discover_wordpress_entrypoints(program)
        functions = _program_functions(program)
        framework_auth = _framework_authorization_evidence(
            entry_points, functions, relative_file
        )
        rest_request_sources = tuple(
            TaintSource(function.parameters[0])
            for entry_point, function in resolve_entrypoint_callbacks(
                entry_points, functions
            )
            if entry_point.kind == "rest" and function.parameters
        )
        analysis: TaintAnalysisResult = analyze_program(
            program,
            sources=DEFAULT_SOURCES + rest_request_sources,
            limits=TaintLimits(max_call_depth=MAX_CALL_DEPTH),
        )
        if not analysis.complete:
            result.complete = False
            result.diagnostics.extend(
                {
                    "file": relative_file,
                    "line": diagnostic.location.line if diagnostic.location else 1,
                    "code": diagnostic.code,
                    "message": diagnostic.message,
                }
                for diagnostic in analysis.diagnostics
            )
            note = "; ".join(item.message for item in analysis.diagnostics)
            result.findings.append(
                _incomplete_finding(
                    relative_file,
                    analysis.diagnostics[0].location.line
                    if analysis.diagnostics and analysis.diagnostics[0].location
                    else 1,
                    f"incomplete taint analysis: {note or 'analysis limit reached'}",
                    "incomplete_taint",
                )
            )
        flow_findings = [
            _finding_from_flow(
                flow,
                _auth_evidence_for_flow(
                    program, flow, relative_file, framework_auth
                ),
                relative_file,
                program,
            )
            for flow in analysis.flows
        ]
        framework_findings = _wordpress_framework_findings(
            program,
            relative_file,
            analysis.flows,
            entry_points,
            framework_auth,
        )
        ajax_sink_lines = {
            (finding["file"], finding["line"])
            for finding in framework_findings
            if finding["type"] == "Unauthenticated WordPress AJAX Action"
        }
        result.findings.extend(
            finding
            for finding in flow_findings
            if not (
                finding.get("context") == "sensitive_action"
                and (finding.get("file"), finding.get("line")) in ajax_sink_lines
            )
        )
        result.findings.extend(framework_findings)
        _annotate_entry_points(
            program, result.findings, relative_file, entry_points
        )

    try:
        if source_file.stat().st_size <= MAX_SOURCE_BYTES:
            source = source_file.read_text(encoding="utf-8", errors="replace")
            result.findings.extend(detect_hardcoded_secrets(source, relative_file))
    except OSError as error:
        result.complete = False
        message = f"Could not inspect source for hardcoded secrets: {error}"
        result.diagnostics.append(
            {
                "file": relative_file,
                "line": 1,
                "code": "secret_read_error",
                "message": message,
            }
        )
        result.findings.append(
            _incomplete_finding(relative_file, 1, message, "secret_read_error")
        )


def scan_php_file_with_summary(path: str | Path) -> ScanSummary:
    """Run only the existing V4 checks against one explicitly supplied PHP file."""
    supplied_path = Path(path).expanduser()
    if supplied_path.is_symlink():
        raise ValueError(f"Refusing to scan a symbolic link: {supplied_path}")
    source_file = supplied_path.resolve()
    if not source_file.is_file():
        raise FileNotFoundError(f"PHP source file not found: {source_file}")
    if source_file.suffix.lower() != ".php":
        raise ValueError(f"Expected a PHP source file: {source_file}")
    root = source_file.parent
    regex_summary = ScanSummary()
    findings, skip_reason = _inspect_file(source_file, root)
    if skip_reason is None:
        regex_summary.scanned_files = 1
        regex_summary.findings.extend(findings)
    else:
        regex_summary.skipped.append(
            {"path": source_file.name, "reason": skip_reason}
        )
    return regex_summary


def scan_php_file_with_taint(
    path: str | Path,
) -> tuple[ScanSummary, TaintScanSummary]:
    """Run existing V4 checks and opt-in taint analysis against one PHP file."""
    source_file = Path(path).expanduser().resolve()
    regex_summary = scan_php_file_with_summary(path)
    taint_summary = TaintScanSummary()
    _analyze_taint_file(source_file, source_file.name, taint_summary)
    _finalize_taint_summary(taint_summary)
    return regex_summary, taint_summary


def list_scan_files(
    path: str | Path, *, max_files: int | None = None
) -> list[Path]:
    """List PHP files that match the scanner's scope without reading contents."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Plugin source directory not found: {root}")
    if max_files is None:
        return [
            source_file
            for source_file in sorted(root.rglob("*"))
            if source_file.is_file() and _is_in_scan_scope(source_file, root)
        ]
    if max_files < 1:
        raise ValueError("File limit must be positive")

    candidates: list[Path] = []
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            directory
            for directory in directories
            if not (current_path / directory).is_symlink()
            and directory.lower() not in IGNORE_DIRS
            and (
                current_path != root
                or directory.lower() in PRIMARY_DIRECTORIES
            )
        )
        for filename in sorted(filenames):
            source_file = current_path / filename
            if (
                source_file.suffix.lower() == ".php"
                and not source_file.is_symlink()
                and (
                    current_path == root
                    or current_path.relative_to(root).parts[0].lower()
                    in PRIMARY_DIRECTORIES
                )
            ):
                candidates.append(source_file)
                if len(candidates) >= max_files:
                    return candidates
    return candidates