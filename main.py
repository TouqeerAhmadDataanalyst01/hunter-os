"""Run offline heuristic checks against locally available WordPress plugins."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import json
import re
import shutil
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from analyzer.platform import SUPPORTED_PLATFORMS, detect_platform
from analyzer.wordpress import (
    list_scan_files,
    scan_plugin,
    scan_plugin_with_summary,
    scan_plugin_with_taint,
    scan_php_file_with_taint,
    scan_php_file_with_summary,
    TaintScanSummary,
    _incomplete_finding,
    _finalize_taint_summary,
)
from duplicate_checker import is_duplicate, record_finding
from reporter.json_report import write_json_report
from reporter.patchstack import append_v5_report, make_report
from tools.download import _extract_archive, get_plugin_local_or_instructions


ROOT = Path(__file__).resolve().parent
TARGETS_FILE = ROOT / "targets" / "wordpress.txt"
LOCAL_PLUGINS = ROOT / "targets" / "plugins"
REPORTS_DIR = ROOT / "reports"
SLUG_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]*")
MAX_MASS_SCAN_FILES = 10_000
DEFAULT_SCAN_TIMEOUT_SECONDS = 120


@dataclass
class ScanResult:
    findings: list[dict[str, object]]
    exit_code: int


def _coverage_after_timeout(
    coverage: dict[str, object], reason: str
) -> dict[str, object]:
    files = [
        dict(entry)
        for entry in coverage.get("files", [])
        if isinstance(entry, dict)
    ]
    for entry in files:
        if entry.get("status") in {"pending", "scanned"}:
            entry["status"] = "skipped"
            entry["reason"] = reason

    status_totals: dict[str, int] = {}
    for entry in files:
        status = str(entry.get("status", "skipped"))
        status_totals[status] = status_totals.get(status, 0) + 1
    non_file_issues = [
        dict(entry)
        for entry in coverage.get("non_file_issues", [])
        if isinstance(entry, dict)
    ]
    non_file_issues.append(
        {
            "kind": "scan",
            "path": "<scan>",
            "status": "skipped",
            "classification": "unknown",
            "reason": reason,
        }
    )
    incomplete_reasons = [
        {
            "path": entry.get("path", "<unknown>"),
            "status": entry.get("status", "skipped"),
            "reason": entry.get("reason", reason),
        }
        for entry in files
        if entry.get("status")
        in {"unsupported", "oversized", "unreadable", "skipped"}
    ]
    incomplete_reasons.extend(
        {
            "path": entry.get("path", "<unknown>"),
            "status": entry.get("status", "skipped"),
            "reason": entry.get("reason", reason),
        }
        for entry in non_file_issues
        if entry.get("status") in {"unsupported", "oversized", "unreadable", "skipped"}
    )
    incomplete_reasons.append(
        {"path": "<scan>", "status": "skipped", "reason": reason}
    )
    return {
        **coverage,
        "complete": False,
        "php_files_by_status": status_totals,
        "incomplete_reasons": incomplete_reasons,
        "non_file_issues": non_file_issues,
        "files": files,
    }


def _legacy_json_records(
    findings: list[dict[str, object]], platform: str = "wordpress"
) -> list[dict[str, object]]:
    return [
        {
            "file": finding["file"],
            "line": finding["line"],
            "type": finding["type"],
            "confidence": finding.get("confidence", "LOW"),
            "auth_present": bool(finding.get("auth_present")),
            "manual_verification_required": True,
            "platform": platform,
            "status": finding.get("status", "POTENTIAL"),
            "evidence": finding.get("evidence", ""),
        }
        for finding in findings
    ]


def load_targets(path: Path = TARGETS_FILE) -> list[str]:
    """Read unique plugin slugs, ignoring blank lines and comments."""
    if not path.is_file():
        raise FileNotFoundError(f"Targets file does not exist: {path}")

    slugs: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        slug = raw_line.split("#", maxsplit=1)[0].strip()
        if slug and slug not in slugs:
            slugs.append(slug)
    return slugs


def scan_target(
    slug: str,
    platform_override: str = "auto",
    dry_run: bool = False,
    reports_dir: Path | None = None,
    engine: str = "regex",
    timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
) -> ScanResult:
    """Scan a local plugin directory or a ZIP already stored in the workspace."""
    if engine not in {"regex", "taint"}:
        print(f"[error] Unsupported analysis engine: {engine}")
        return ScanResult([], 2)
    if timeout_seconds < 1:
        print("[error] Scan timeout must be a positive number of seconds.")
        return ScanResult([], 2)
    report_root = reports_dir if reports_dir is not None else REPORTS_DIR
    if not SLUG_PATTERN.fullmatch(slug):
        print(f"[skip] Invalid plugin slug: {slug!r}")
        return ScanResult([], 2)

    try:
        plugin_path = get_plugin_local_or_instructions(slug)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"[error] Could not prepare local source for {slug}: {error}")
        return ScanResult([], 2)
    if plugin_path is None:
        print(f"[skip] No local source was found for {slug}.")
        return ScanResult([], 2)

    try:
        platform = (
            detect_platform(plugin_path)
            if platform_override == "auto"
            else platform_override
        )
    except NotADirectoryError as error:
        print(f"[error] Could not identify platform: {error}")
        return ScanResult([], 4)
    if platform is None:
        print("[skip] Could not detect a supported project platform.")
        return ScanResult([], 3)

    print(f"[platform] {platform}")
    if platform != "wordpress":
        print(
            f"[manual] Platform detected, but no {platform} security rules are "
            "implemented. No vulnerability scan was performed."
        )
        return ScanResult([], 3)

    if dry_run:
        try:
            candidates = list_scan_files(plugin_path)
        except NotADirectoryError as error:
            print(f"[error] Could not list source files: {error}")
            return ScanResult([], 4)
        print(f"[dry-run] Eligible PHP files: {len(candidates)}")
        for candidate in candidates:
            print(f"  {candidate.relative_to(plugin_path).as_posix()}")
        return ScanResult([], 0)

    print(f"[scan] Checking local source: {plugin_path}")
    if engine == "taint":
        started = time.monotonic()
        executor = ThreadPoolExecutor(max_workers=1)
        taint_future = executor.submit(
            scan_plugin_with_taint,
            plugin_path,
            timeout_seconds=timeout_seconds,
            max_files=MAX_MASS_SCAN_FILES,
        )
        summary = scan_plugin_with_summary(plugin_path)
        remaining = max(0.0, timeout_seconds - (time.monotonic() - started))
        try:
            taint_summary = taint_future.result(timeout=remaining)
        except FutureTimeoutError:
            taint_future.cancel()
            timeout_message = f"taint scan exceeded {timeout_seconds} seconds"
            taint_summary = TaintScanSummary(
                findings=[
                    _incomplete_finding(
                        "<scan>",
                        1,
                        timeout_message,
                        "timeout",
                    )
                ],
                complete=False,
                coverage=_coverage_after_timeout(
                    summary.coverage, timeout_message
                ),
                diagnostics=[
                    {
                        "file": "<scan>",
                        "line": 1,
                        "code": "timeout",
                        "message": timeout_message,
                    }
                ],
            )
            _finalize_taint_summary(taint_summary)
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
    else:
        summary = scan_plugin_with_summary(plugin_path)
        taint_summary = None
    findings = summary.findings
    print(f"[scan] Source files checked by the existing heuristics: {summary.scanned_files}")
    skipped_by_reason: dict[str, list[str]] = {}
    for skipped in summary.skipped:
        skipped_by_reason.setdefault(skipped["reason"], []).append(skipped["path"])
    for reason, paths in sorted(skipped_by_reason.items()):
        print(f"[scan] Not analyzed ({reason}): {len(paths)} path(s)")
        for skipped_path in paths[:5]:
            print(f"  {skipped_path}")
        if len(paths) > 5:
            print(f"  ... and {len(paths) - 5} more")
    auth_count = sum(bool(finding.get("auth_present")) for finding in findings)
    print(
        f"[scan] Potential findings: {len(findings)}; "
        f"nearby auth signals to review: {auth_count}."
    )
    if taint_summary is not None:
        coverage = taint_summary.coverage
        print(
            f"[coverage] PHP files: {coverage.get('discovered_php_files', 0)}; "
            f"complete: {coverage.get('complete', False)}; "
            f"statuses: {coverage.get('php_files_by_status', {})}."
        )
    if taint_summary is None:
        json_path = write_json_report(slug, platform, findings, report_root)
    else:
        active_taint_findings = [
            finding
            for finding in taint_summary.findings
            if finding.get("status") != "DOWNGRADED"
        ]
        print(
            f"[taint] Active findings: {len(active_taint_findings)}; "
            f"judge downgrades: {len(taint_summary.audit)}; "
            f"analysis complete: {taint_summary.complete}."
        )
        json_path = write_json_report(
            slug,
            platform,
            findings,
            report_root,
            v5_taint_findings=active_taint_findings,
            v5_audit=taint_summary.audit,
            v5_coverage=taint_summary.coverage,
        )
    print(f"[report] Saved current-run JSON to {json_path}")

    for finding in findings:
        file_name = str(finding["file"])
        line_no = int(finding["line"])
        if finding.get("auth_present"):
            print(f"[review] {file_name}:{line_no} has nearby auth token {finding['auth_check']!r}.")
        if is_duplicate(slug, file_name, line_no):
            print(f"[duplicate] {file_name}:{line_no} was seen in the last 14 days.")
            continue

        report_path = make_report(slug, finding, reports_dir=report_root)
        record_finding(slug, file_name, line_no, reports_dir=report_root)
        print(f"[report] Saved local review notes to {report_path}")

    if taint_summary is not None:
        v5_report_path = append_v5_report(
            slug,
            [
                finding
                for finding in taint_summary.findings
                if finding.get("status") != "DOWNGRADED"
            ],
            taint_summary.audit,
            report_root,
            coverage=taint_summary.coverage,
        )
        if v5_report_path is not None:
            print(f"[report] Saved V5 taint evidence to {v5_report_path}")

    return ScanResult(
        findings,
        1
        if findings
        or (
            taint_summary
            and any(
                finding.get("status") != "DOWNGRADED"
                for finding in taint_summary.findings
            )
        )
        or (taint_summary and not taint_summary.coverage.get("complete", True))
        else 0,
    )


def _scan_slug(path: Path) -> str:
    raw_name = path.stem if path.is_file() else path.name
    slug = re.sub(r"[^a-z0-9_-]+", "-", raw_name.casefold()).strip("-_")
    if not slug or not slug[0].isalnum():
        slug = f"scan-{slug}"
    return slug[:64]


def scan_source_path(
    path: str | Path,
    *,
    engine: str = "regex",
    reports_dir: Path | None = None,
    timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
) -> ScanResult:
    """Scan a local source directory or safely extract and scan a ZIP."""
    source_path = Path(path).expanduser()
    if engine not in {"regex", "taint"}:
        print(f"[error] Unsupported analysis engine: {engine}")
        return ScanResult([], 2)
    if timeout_seconds < 1:
        print("[error] Scan timeout must be a positive number of seconds.")
        return ScanResult([], 2)
    if source_path.is_symlink():
        print(f"[error] Refusing a symbolic-link scan target: {source_path}")
        return ScanResult([], 2)
    source_path = source_path.resolve()
    report_root = reports_dir if reports_dir is not None else REPORTS_DIR
    slug = _scan_slug(source_path)
    extraction_path: Path | None = None

    try:
        if source_path.is_dir():
            scan_root = source_path
        elif source_path.is_file() and source_path.suffix.casefold() == ".zip":
            extraction_path = Path(
                tempfile.mkdtemp(prefix=f"hunter-os-mass-{slug}-")
            )
            scan_root = _extract_archive(source_path, extraction_path)
        else:
            print(f"[error] Expected a source directory or ZIP archive: {source_path}")
            return ScanResult([], 2)

        platform = detect_platform(scan_root)
        if platform != "wordpress":
            print(
                "[manual] No tested WordPress analysis path was selected for this "
                "source. No vulnerability scan was performed."
            )
            return ScanResult([], 3)

        print(f"[scan] Scanning local source: {scan_root}")
        started = time.monotonic()
        if engine == "taint":
            executor = ThreadPoolExecutor(max_workers=1)
            taint_future = executor.submit(
                scan_plugin_with_taint,
                scan_root,
                timeout_seconds=timeout_seconds,
                max_files=MAX_MASS_SCAN_FILES,
            )
            summary = scan_plugin_with_summary(
                scan_root, max_files=MAX_MASS_SCAN_FILES
            )
            remaining = max(0.0, timeout_seconds - (time.monotonic() - started))
            try:
                taint_summary = taint_future.result(timeout=remaining)
            except FutureTimeoutError:
                taint_future.cancel()
                timeout_message = f"taint scan exceeded {timeout_seconds} seconds"
                taint_summary = TaintScanSummary(
                    findings=[
                        _incomplete_finding(
                            "<scan>",
                            1,
                            timeout_message,
                            "timeout",
                        )
                    ],
                    complete=False,
                    coverage=_coverage_after_timeout(
                        summary.coverage, timeout_message
                    ),
                    diagnostics=[
                        {
                            "file": "<scan>",
                            "line": 1,
                            "code": "timeout",
                            "message": timeout_message,
                        }
                    ],
                )
                _finalize_taint_summary(taint_summary)
            finally:
                executor.shutdown(wait=True, cancel_futures=True)
        else:
            summary = scan_plugin_with_summary(
                scan_root, max_files=MAX_MASS_SCAN_FILES
            )
            taint_summary = None

        findings = summary.findings
        if taint_summary is None:
            report_path = write_json_report(slug, platform, findings, report_root)
        else:
            active_taint = [
                finding
                for finding in taint_summary.findings
                if finding.get("status") != "DOWNGRADED"
            ]
            report_path = write_json_report(
                slug,
                platform,
                findings,
                report_root,
                v5_taint_findings=active_taint,
                v5_audit=taint_summary.audit,
                v5_coverage=taint_summary.coverage,
            )

        for finding in findings:
            file_name = str(finding["file"])
            line_no = int(finding["line"])
            if is_duplicate(slug, file_name, line_no, reports_dir=report_root):
                print(f"[duplicate] {file_name}:{line_no} was seen in the last 14 days.")
                continue
            report = make_report(slug, finding, reports_dir=report_root)
            record_finding(slug, file_name, line_no, reports_dir=report_root)
            print(f"[report] Saved local review notes to {report}")
        if taint_summary is not None:
            v5_report_path = append_v5_report(
                slug,
                [
                    finding
                    for finding in taint_summary.findings
                    if finding.get("status") != "DOWNGRADED"
                ],
                taint_summary.audit,
                report_root,
                coverage=taint_summary.coverage,
            )
            if v5_report_path is not None:
                print(f"[report] Saved V5 taint evidence to {v5_report_path}")
        print(f"[report] Saved current-run JSON to {report_path}")
        return ScanResult(
            findings,
            1
            if findings
            or (
                taint_summary
                and any(
                    finding.get("status") != "DOWNGRADED"
                    for finding in taint_summary.findings
                )
            )
            or (
                taint_summary
                and not taint_summary.coverage.get("complete", True)
            )
            else 0,
        )
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        print(f"[error] Could not scan source: {error}")
        return ScanResult([], 2)
    finally:
        if extraction_path is not None:
            shutil.rmtree(extraction_path, ignore_errors=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan local WordPress plugin source.")
    parser.add_argument("--target", help="scan only this slug from targets/wordpress.txt")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list eligible files without running heuristics or writing reports",
    )
    parser.add_argument(
        "--platform",
        choices=("auto", *SUPPORTED_PLATFORMS),
        default="auto",
        help="detect automatically or select a platform explicitly",
    )
    parser.add_argument(
        "--engine",
        choices=("regex", "taint"),
        default="regex",
        help="regex preserves V4 behavior; taint adds opt-in parser/data-flow results",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help="maximum taint analysis time budget in seconds (default: 120)",
    )
    parser.add_argument(
        "source_file",
        nargs="?",
        help="scan one PHP file, or scan a folder/ZIP with either engine",
    )
    args = parser.parse_args(argv)

    if args.source_file is not None:
        requested_path = Path(args.source_file).expanduser()
        if requested_path.is_dir() or requested_path.suffix.casefold() == ".zip":
            result = scan_source_path(
                requested_path,
                engine=args.engine,
                timeout_seconds=args.timeout,
            )
            return result.exit_code
        if args.engine != "taint":
            try:
                regex_summary = scan_php_file_with_summary(requested_path)
            except (OSError, ValueError) as error:
                print(f"[error] Could not scan PHP source: {error}")
                return 2
            records = _legacy_json_records(regex_summary.findings)
            print(json.dumps(records, indent=2))
            return 1 if records else 0
        try:
            regex_summary, taint_summary = scan_php_file_with_taint(args.source_file)
        except (OSError, ValueError) as error:
            print(f"[error] Could not scan PHP source: {error}")
            return 2
        records = _legacy_json_records(regex_summary.findings)
        active_taint_findings = [
            finding
            for finding in taint_summary.findings
            if finding.get("status") != "DOWNGRADED"
        ]
        print(
            json.dumps(
                {
                    "findings": records,
                    "v5_taint_findings": active_taint_findings,
                    "v5_audit": taint_summary.audit,
                    "v5_coverage": taint_summary.coverage,
                },
                indent=2,
            )
        )
        return (
            1
            if records
            or active_taint_findings
            or not taint_summary.coverage.get("complete", True)
            else 0
        )

    print("Hunter OS v4: offline project identification and WordPress source review")
    print("No remote downloads, vulnerability-site requests, or exploit requests are made.")
    try:
        slugs = load_targets()
    except (OSError, UnicodeError) as error:
        print(f"[error] Could not read targets: {error}")
        return 2

    if not slugs:
        print("[info] No plugin slugs are listed in targets/wordpress.txt.")
        return 2

    if args.target:
        if args.target not in slugs:
            print(f"[error] Target is not listed in {TARGETS_FILE}: {args.target}")
            return 2
        slugs = [args.target]

    exit_code = 0
    for slug in slugs:
        print(f"\n[target] {slug}")
        result = scan_target(
            slug,
            platform_override=args.platform,
            dry_run=args.dry_run,
            engine=args.engine,
            timeout_seconds=args.timeout,
        )
        exit_code = max(exit_code, result.exit_code)

    print("\nDone. Heuristic matches require manual verification and authorization.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())