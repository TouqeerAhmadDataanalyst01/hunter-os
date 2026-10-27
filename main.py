"""Run offline heuristic checks against locally available WordPress plugins."""

from __future__ import annotations

import argparse
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from analyzer.platform import SUPPORTED_PLATFORMS, detect_platform
from analyzer.wordpress import list_scan_files, scan_plugin
from duplicate_checker import is_duplicate, record_finding
from reporter.json_report import write_json_report
from reporter.patchstack import make_report
from tools.download import get_plugin_local_or_instructions


ROOT = Path(__file__).resolve().parent
TARGETS_FILE = ROOT / "targets" / "wordpress.txt"
LOCAL_PLUGINS = ROOT / "targets" / "plugins"
REPORTS_DIR = ROOT / "reports"
SLUG_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]*")


@dataclass
class ScanResult:
    findings: list[dict[str, object]]
    exit_code: int


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
) -> ScanResult:
    """Scan a local plugin directory or a ZIP already stored in the workspace."""
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
    findings = scan_plugin(plugin_path)
    auth_count = sum(bool(finding.get("auth_present")) for finding in findings)
    print(
        f"[scan] Potential findings: {len(findings)}; "
        f"nearby auth signals to review: {auth_count}."
    )
    json_path = write_json_report(slug, platform, findings, report_root)
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

    return ScanResult(findings, 1 if findings else 0)


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
    args = parser.parse_args(argv)

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
        )
        exit_code = max(exit_code, result.exit_code)

    print("\nDone. Heuristic matches require manual verification and authorization.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())