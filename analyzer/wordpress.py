"""Conservative, regex-based heuristics for local WordPress PHP source."""

from __future__ import annotations

import re
from pathlib import Path


PHP_SUFFIXES = {".php", ".phtml", ".php3", ".inc"}
MAX_SOURCE_BYTES = 2_000_000


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _context(text: str, line: int, radius: int = 2) -> str:
    lines = text.splitlines()
    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    return "\n".join(
        f"{index + 1}: {lines[index]}" for index in range(start, end)
    )


def _inspect_file(path: Path, root: Path) -> list[dict[str, object]]:
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    relative_file = path.relative_to(root).as_posix()
    findings: list[dict[str, object]] = []

    checks = (
        (
            "Unauthenticated File Upload",
            re.compile(r"\$_FILES\b", re.IGNORECASE),
            re.compile(r"current_user_can|check_admin_referer|wp_verify_nonce", re.I),
            "File upload input is present, but no capability or nonce check was found in this file.",
        ),
        (
            "Unauthenticated SQL Injection",
            re.compile(
                r"\$wpdb\s*->\s*query\s*\([^;]{0,500}?\$_POST\b",
                re.IGNORECASE,
            ),
            re.compile(r"\$_POST\b", re.IGNORECASE),
            "A database query call and POST input occur in this file; verify that values are validated and parameterized.",
        ),
        (
            "Auth Bypass",
            re.compile(
                r"\$_COOKIE\b[\s\S]{0,300}?(?:==\s*true|true\s*==)", re.IGNORECASE
            ),
            re.compile(r"(?:==\s*true|true\s*==)", re.IGNORECASE),
            "Cookie input and a comparison with true occur in this file; review the authorization logic.",
        ),
    )

    for finding_type, primary_pattern, secondary_pattern, description in checks:
        if finding_type == "Unauthenticated File Upload":
            if not primary_pattern.search(text) or secondary_pattern.search(text):
                continue
            match = primary_pattern.search(text)
        elif finding_type == "Unauthenticated SQL Injection":
            match = primary_pattern.search(text)
            if not match:
                continue
        else:
            match = primary_pattern.search(text)
            if not match:
                continue

        assert match is not None
        line = _line_for(text, match.start())
        findings.append(
            {
                "file": relative_file,
                "line": line,
                "type": finding_type,
                "description": description,
                "evidence": _context(text, line),
                "poc": "Not generated. Review and validate only in an authorized local test environment.",
            }
        )

    return findings


def scan_plugin(path: str | Path) -> list[dict[str, object]]:
    """Scan a local plugin directory and return heuristic source findings.

    The checks are intentionally limited to source inspection: they make no
    network requests and do not claim that a match is an exploitable bug.
    """
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Plugin source directory not found: {root}")

    findings: list[dict[str, object]] = []
    for source_file in sorted(root.rglob("*")):
        if source_file.is_file() and source_file.suffix.lower() in PHP_SUFFIXES:
            findings.extend(_inspect_file(source_file, root))
    return findings