"""Conservative, regex-based heuristics for local WordPress PHP source."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


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