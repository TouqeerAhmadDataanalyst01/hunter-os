"""Write local Markdown review notes with a Patchstack-style section layout."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORTS_DIR = ROOT / "reports"

REMEDIATION_BY_TYPE = {
    "Cross-Site Scripting (XSS)": (
        "Wrap output with esc_html() (or the escaping function for its exact context)."
    ),
    "SQL Injection": (
        "Use parameterized queries or prepared statements; do not concatenate "
        "untrusted input into SQL."
    ),
    "Unsafe File Upload": (
        "Validate authorization, file type, and extension, and store uploads "
        "outside executable or public paths."
    ),
    "Directory Traversal / Local File Inclusion": (
        "Resolve paths against a fixed base directory and verify the normalized "
        "target remains inside it."
    ),
    "Command Injection": (
        "Avoid shell execution; use fixed executable and argument lists, and "
        "validate any required input."
    ),
    "Server-Side Request Forgery": (
        "Restrict outbound requests to an allowlist and validate resolved "
        "destinations."
    ),
    "Hardcoded Secret": (
        "Remove the credential from source and rotate it if it may be active."
    ),
    "Unauthenticated WordPress AJAX Action": (
        "Require an appropriate capability check in the callback; a nonce alone "
        "is not authorization."
    ),
    "WordPress REST Route Authorization": (
        "Require a permission callback that enforces the intended capability; "
        "a nonce alone is not authorization."
    ),
}

WHY_BY_TYPE = {
    "Cross-Site Scripting (XSS)": (
        "Request-controlled data reaches HTML output without effective output escaping."
    ),
    "SQL Injection": (
        "Request-controlled data reaches a database query without effective preparation."
    ),
    "Unauthenticated WordPress AJAX Action": (
        "A registered AJAX callback performs a sensitive action without proven capability authorization."
    ),
    "WordPress REST Route Authorization": (
        "A REST callback handles tainted data without a proven restrictive permission callback."
    ),
    "Directory Traversal / Local File Inclusion": (
        "Request-controlled data reaches a file path operation."
    ),
    "Unsafe File Upload": (
        "Untrusted upload data reaches a file-handling operation."
    ),
    "Command Injection": (
        "Request-controlled data reaches a command execution operation."
    ),
    "Server-Side Request Forgery": (
        "Request-controlled data reaches an outbound request destination."
    ),
    "Hardcoded Secret": (
        "A credential-like value appears to be embedded in source code."
    ),
}


def _safe_slug(slug: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", slug):
        raise ValueError(f"Invalid plugin slug: {slug!r}")
    return slug


def _markdown_text(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    for character in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "#", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def _markdown_code(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    longest_backticks = max(
        (len(match.group(0)) for match in re.finditer(r"`+", text)),
        default=0,
    )
    delimiter = "`" * (longest_backticks + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{delimiter}{padding}{text}{padding}{delimiter}"


def _record_location(record: dict[str, object], fallback_file: object) -> str:
    file_name = record.get("file", fallback_file)
    line = record.get("line", "?")
    return f"{str(file_name).replace(chr(10), ' ')}:{str(line).replace(chr(10), ' ')}"


def _render_evidence(
    heading: str,
    evidence: object,
    fallback_file: object,
) -> list[str]:
    lines = [f"**{heading}:**"]
    if not isinstance(evidence, list) or not evidence:
        lines.append("- None observed.")
        return lines
    for item in evidence:
        if not isinstance(item, dict):
            lines.append(f"- {_markdown_text(item)}")
            continue
        name = _markdown_code(item.get("name", item.get("proof", "evidence")))
        location = _record_location(item, fallback_file)
        details: list[str] = []
        if "effective" in item:
            details.append(f"effective: {_markdown_text(item['effective'])}")
        if item.get("effective_contexts"):
            contexts = ", ".join(
                _markdown_text(context)
                for context in item["effective_contexts"]
            )
            details.append(f"contexts: {contexts}")
        if item.get("proof"):
            details.append(_markdown_text(item["proof"]))
        suffix = f" ({'; '.join(details)})" if details else ""
        lines.append(f"- {name} at {_markdown_code(location)}{suffix}")
    return lines


def _render_finding(finding: dict[str, object], index: int) -> list[str]:
    finding_type = str(finding.get("type", "Potential security issue"))
    file_name = finding.get("file", "<unknown>")
    location = _record_location(finding, file_name)
    function = finding.get("function")
    title = _markdown_text(finding_type)
    if function:
        title += f" in function {_markdown_code(function)}"
    lines = [
        f"### {index}. {title}",
        "",
        f"**File:** {_markdown_code(location)}",
        (
            f"**Confidence:** {_markdown_text(finding.get('confidence', 'unknown'))} -- "
            f"{_markdown_text(finding.get('confidence_reason', 'Manual review required.'))}"
        ),
        f"**Entry point:** {_markdown_text(finding.get('entry_point', 'unknown'))}",
        f"**Status:** {_markdown_text(finding.get('status', 'POTENTIAL'))}",
        "",
    ]
    trace = finding.get("trace")
    if isinstance(trace, list) and trace:
        trace_parts: list[str] = []
        for step in trace:
            if not isinstance(step, dict):
                trace_parts.append(_markdown_text(step))
                continue
            name = str(step.get("name", step.get("kind", "step"))).replace("\n", " ")
            step_line = step.get("line", "?")
            trace_parts.append(
                f"line {_markdown_text(step_line)} {_markdown_code(name)}"
            )
        lines.extend([
            "",
            "**Trace:** " + " -> ".join(trace_parts),
        ])
    else:
        lines.extend(["", "**Trace:** No source-to-sink trace is available."])
    why = WHY_BY_TYPE.get(
        finding_type,
        "Static analysis observed evidence that needs review in its source context.",
    )
    lines.extend(["", f"**Why it matters:** {_markdown_text(why)}"])
    lines.extend(["", *_render_evidence(
        "Sanitizer evidence",
        finding.get("sanitizer_evidence"),
        file_name,
    )])
    lines.extend(["", *_render_evidence(
        "Authorization evidence",
        finding.get("auth_evidence"),
        file_name,
    )])
    remediation = REMEDIATION_BY_TYPE.get(
        finding_type,
        "Review the source-to-sink path and apply validation or protection "
        "appropriate to this sink's security context.",
    )
    lines.extend([
        "",
        f"**Fix suggestion:** {_markdown_text(remediation)}",
    ])
    if finding.get("note"):
        lines.extend(["", f"**Manual review note:** {_markdown_text(finding['note'])}"])
    return lines


def append_v5_report(
    slug: str,
    findings: list[dict[str, object]],
    audit: list[dict[str, object]],
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> Path | None:
    """Append V5 taint evidence without changing legacy V4-only report bytes."""
    safe_slug = _safe_slug(slug)
    if not findings and not audit:
        return None

    report_directory = reports_dir / safe_slug
    report_directory.mkdir(parents=True, exist_ok=True)
    report_path = report_directory / "report_patchstack.md"
    lines = ["## V5 Taint Analysis", ""]
    for index, finding in enumerate(findings, start=1):
        lines.extend(_render_finding(finding, index))
        lines.extend(["", "---", ""])

    if audit:
        lines.extend(["## V5 Audit (`v5_audit`)", ""])
        for index, item in enumerate(audit, start=1):
            if not isinstance(item, dict):
                lines.extend([f"### {index}. {_markdown_text(item)}", ""])
                continue
            finding = item.get("finding")
            finding_record = finding if isinstance(finding, dict) else {}
            finding_type = _markdown_text(
                finding_record.get("type", "Downgraded finding")
            )
            function = finding_record.get("function")
            if function:
                finding_type += f" in function {_markdown_code(function)}"
            location = _record_location(
                finding_record,
                finding_record.get("file", "<unknown>"),
            )
            confidence_line = (
                f"**Confidence:** {_markdown_text(item.get('downgraded_confidence', 'low'))} "
                "-- analysis incomplete; findings may be absent."
                if str(item.get("reason", "")).startswith("analysis incomplete")
                else (
                    "**Confidence:** "
                    f"{_markdown_text(item.get('original_confidence', 'unknown'))} "
                    "downgraded to "
                    f"{_markdown_text(item.get('downgraded_confidence', 'low'))}"
                )
            )
            lines.extend([
                f"### {index}. {finding_type}",
                "",
                f"**Location:** {_markdown_code(location)}",
                f"**Reason:** {_markdown_text(item.get('reason', 'Not specified'))}",
                confidence_line,
                "",
            ])
            trace = finding_record.get("trace")
            if isinstance(trace, list) and trace:
                lines.extend(["**Source-to-sink trace:**"])
                for step in trace:
                    if not isinstance(step, dict):
                        lines.append(f"- {_markdown_text(step)}")
                        continue
                    kind = str(step.get("kind", "step")).replace("\n", " ")
                    name = str(step.get("name", kind)).replace("\n", " ")
                    step_location = _record_location(
                        step,
                        finding_record.get("file", "<unknown>"),
                    )
                    lines.append(
                        f"- {_markdown_code(f'{kind}: {name}')} at "
                        f"{_markdown_code(step_location)}"
                    )
                lines.append("")
            lines.extend(_render_evidence(
                "Sanitizer evidence",
                item.get("sanitizer_evidence"),
                finding_record.get("file", "<unknown>"),
            ))
            lines.extend([""])
            lines.extend(_render_evidence(
                "Authorization evidence",
                item.get("auth_evidence"),
                finding_record.get("file", "<unknown>"),
            ))
            if item.get("note"):
                lines.extend(["", f"**Judge note:** {_markdown_text(item['note'])}"])
            lines.append("")

    section = "\n".join(lines).rstrip() + "\n"
    existing = (
        report_path.read_text(encoding="utf-8")
        if report_path.exists()
        else ""
    )
    if section in existing:
        return report_path
    with report_path.open("a", encoding="utf-8") as report_file:
        if existing:
            report_file.write("\n---\n\n")
        report_file.write(section)
    return report_path


def make_report(
    slug: str,
    finding: dict[str, object],
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> Path:
    """Save a source-review note; no exploit payload or CVSS score is invented."""
    safe_slug = _safe_slug(slug)
    report_directory = reports_dir / safe_slug
    report_directory.mkdir(parents=True, exist_ok=True)
    report_path = report_directory / "report_patchstack.md"

    title = f"Potential {finding['type']} in {safe_slug}"
    content = f"""# {title}

## Description

{finding['description']}

This is a static-analysis heuristic, not a confirmed vulnerability. Review the surrounding code, data flow, and access controls before drawing conclusions.

**Source:** `{finding['file']}` at line {finding['line']}

**Confidence:** {finding.get('confidence', 'LOW')}

**Nearby auth token:** {finding.get('auth_check') or 'None detected in the preceding 50 lines'}

**Manual verification required:** Yes

## PoC

No exploit request is generated. Validate behavior only in a local, isolated environment for which you have authorization.

## Impact

Not assessed. Impact depends on reachability, authentication requirements, input validation, and deployment configuration.

## CVSS

Not scored. A CVSS score requires manual validation and a confirmed impact assessment.

## Evidence

```text
{finding['evidence']}
```
"""
    should_separate = report_path.exists() and report_path.stat().st_size > 0
    with report_path.open("a", encoding="utf-8") as report_file:
        if should_separate:
            report_file.write("\n---\n\n")
        report_file.write(content)
    return report_path