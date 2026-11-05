"""Conservative, regex-based heuristics for local WordPress PHP source."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from analyzer.php_parser import (
    Assignment,
    Call,
    CallStatement,
    Expression,
    FunctionDef,
    IfStatement,
    Program,
    ReturnStatement,
    SourceLocation,
    Statement,
    parse_php_file,
)
from analyzer.taint import (
    DEFAULT_SANITIZERS,
    TaintAnalysisResult,
    TaintFlow,
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


@dataclass
class ScanSummary:
    findings: list[dict[str, object]] = field(default_factory=list)
    scanned_files: int = 0
    skipped: list[dict[str, str]] = field(default_factory=list)


@dataclass
class TaintScanSummary:
    findings: list[dict[str, object]] = field(default_factory=list)
    audit: list[dict[str, object]] = field(default_factory=list)
    diagnostics: list[dict[str, object]] = field(default_factory=list)
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


def scan_plugin_with_summary(path: str | Path) -> ScanSummary:
    """Run the existing heuristics and return visible file dispositions."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Plugin source directory not found: {root}")

    summary = ScanSummary()
    walk_errors: list[OSError] = []

    def record_walk_error(error: OSError) -> None:
        walk_errors.append(error)

    candidates: list[Path] = []
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
            else:
                summary.skipped.append(
                    {"path": relative, "reason": "out of scan scope"}
                )

    for error in walk_errors:
        try:
            relative = Path(error.filename or root).relative_to(root).as_posix()
        except ValueError:
            relative = str(error.filename or root)
        summary.skipped.append(
            {"path": relative, "reason": "unreadable directory"}
        )

    for source_file in sorted(candidates):
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
        in {"current_user_can", "user_can"}
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
    program: Program, flow: TaintFlow, relative_file: str
) -> list[dict[str, object]]:
    scopes: list[tuple[str, tuple[Statement, ...]]] = [
        ("<top-level>", tuple(program.statements))
    ]
    functions: list[FunctionDef] = list(program.functions)
    for class_def in program.classes:
        functions.extend(class_def.methods)
    for function in functions:
        scope_name = (
            f"{function.class_name}::{function.name}"
            if function.class_name
            else function.name
        )
        scopes.append((scope_name, tuple(function.body)))

    for scope_name, statements in scopes:
        calls = _scope_calls(statements)
        sink_in_scope = any(
            call.location.file == flow.sink.location.file
            and call.location.offset == flow.sink.location.offset
            for call in calls
        )
        if not sink_in_scope:
            continue
        return _guard_evidence_in_scope(
            statements, flow.sink.location, scope_name, relative_file
        )
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
    finding: dict[str, object] = {
        "file": relative_file,
        "line": flow.sink.location.line,
        "type": f"Tainted data reaches {flow.context} sink {flow.sink.name}",
        "status": "POTENTIAL",
        "confidence": "medium",
        "context": flow.context,
        "source": source,
        "sink": sink,
        "trace": trace,
        "sanitizer_evidence": sanitizer_evidence,
        "auth_evidence": auth_evidence,
        "note": "Source-to-sink evidence requires manual review; authorization is not inferred from nearby tokens.",
    }
    return finding


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
            reasons.append("same-function authorization call before sink")
        if not reasons:
            continue
        original_confidence = finding["confidence"]
        finding["confidence"] = "low"
        finding["status"] = "DOWNGRADED"
        audit.append(
            {
                "finding_index": index,
                "reason": "; ".join(reasons),
                "original_confidence": original_confidence,
                "downgraded_confidence": "low",
                "sanitizer_evidence": sanitizer_evidence,
                "auth_evidence": auth_evidence,
                "finding": dict(finding),
                "note": "Judge V2 stub downgraded but preserved the flow; this is not proof of safety.",
            }
        )
    return audit


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
        "trace": [],
        "sanitizer_evidence": [],
        "auth_evidence": [],
        "note": f"incomplete parse: {message}" if kind == "incomplete_parse" else message,
    }


def scan_plugin_with_taint(path: str | Path) -> TaintScanSummary:
    """Run V4 regex checks and opt-in parser/taint analysis side by side."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Plugin source directory not found: {root}")

    result = TaintScanSummary()
    candidates = [
        source_file
        for source_file in list_scan_files(root)
        if not source_file.is_symlink()
    ]
    for source_file in candidates:
        relative_file = source_file.relative_to(root).as_posix()
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
            continue

        analysis: TaintAnalysisResult = analyze_program(program)
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
        for flow in analysis.flows:
            result.findings.append(
                _finding_from_flow(
                    flow,
                    _auth_evidence_for_flow(program, flow, relative_file),
                    relative_file,
                )
            )

    result.audit = _judge_taint_findings(result.findings)
    return result


def list_scan_files(path: str | Path) -> list[Path]:
    """List PHP files that match the scanner's scope without reading contents."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Plugin source directory not found: {root}")
    return [
        source_file
        for source_file in sorted(root.rglob("*"))
        if source_file.is_file() and _is_in_scan_scope(source_file, root)
    ]