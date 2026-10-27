"""Run offline heuristic checks against locally available WordPress plugins."""

from __future__ import annotations

import argparse
import re
import zipfile
from pathlib import Path

from analyzer.platform import SUPPORTED_PLATFORMS, detect_platform
from analyzer.wordpress import scan_plugin
from duplicate_checker import is_duplicate, record_finding
from reporter.patchstack import make_report
from tools.download import get_plugin_local_or_instructions


ROOT = Path(__file__).resolve().parent
TARGETS_FILE = ROOT / "targets" / "wordpress.txt"
LOCAL_PLUGINS = ROOT / "targets" / "plugins"
REPORTS_DIR = ROOT / "reports"
SLUG_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]*")


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


def scan_target(slug: str, platform_override: str = "auto") -> list[dict[str, object]]:
    """Scan a local plugin directory or a ZIP already stored in the workspace."""
    if not SLUG_PATTERN.fullmatch(slug):
        print(f"[skip] Invalid plugin slug: {slug!r}")
        return []

    try:
        plugin_path = get_plugin_local_or_instructions(slug)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"[error] Could not prepare local source for {slug}: {error}")
        return []
    if plugin_path is None:
        print(f"[skip] No local source was found for {slug}.")
        return []

    try:
        platform = (
            detect_platform(plugin_path)
            if platform_override == "auto"
            else platform_override
        )
    except NotADirectoryError as error:
        print(f"[error] Could not identify platform: {error}")
        return []
    if platform is None:
        print("[skip] Could not detect a supported project platform.")
        return []

    print(f"[platform] {platform}")
    if platform != "wordpress":
        print(
            f"[manual] Platform detected, but no {platform} security rules are "
            "implemented. No vulnerability scan was performed."
        )
        return []

    print(f"[scan] Checking local source: {plugin_path}")
    findings = scan_plugin(plugin_path)
    safe_count = sum(
        finding.get("status") == "LIKELY SAFE - has auth check" for finding in findings
    )
    print(
        f"[scan] Potential findings: {len(findings) - safe_count}; "
        f"LIKELY SAFE matches: {safe_count}."
    )

    for finding in findings:
        file_name = str(finding["file"])
        line_no = int(finding["line"])
        if finding.get("status") == "LIKELY SAFE - has auth check":
            print(
                f"[LIKELY SAFE] {file_name}:{line_no} has nearby auth check "
                f"{finding['auth_check']!r}; not reported as a bug."
            )
            continue
        if is_duplicate(slug, file_name, line_no):
            print(f"[duplicate] {file_name}:{line_no} was seen in the last 14 days.")
            continue

        report_path = make_report(slug, finding, reports_dir=REPORTS_DIR)
        record_finding(slug, file_name, line_no, reports_dir=REPORTS_DIR)
        print(f"[report] Saved local review notes to {report_path}")

    return findings


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Scan local WordPress plugin source.")
    parser.add_argument("--target", help="scan only this slug from targets/wordpress.txt")
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
        return

    if not slugs:
        print("[info] No plugin slugs are listed in targets/wordpress.txt.")
        return

    if args.target:
        if args.target not in slugs:
            print(f"[error] Target is not listed in {TARGETS_FILE}: {args.target}")
            return
        slugs = [args.target]

    for slug in slugs:
        print(f"\n[target] {slug}")
        scan_target(slug, platform_override=args.platform)

    print("\nDone. Heuristic matches require manual verification and authorization.")


if __name__ == "__main__":
    main()