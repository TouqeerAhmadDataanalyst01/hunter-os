"""Write a machine-readable record of one local scan's heuristic matches."""

from __future__ import annotations

import json
import re
from pathlib import Path


def write_json_report(
    slug: str,
    platform: str,
    findings: list[dict[str, object]],
    reports_dir: Path,
) -> Path:
    """Write current-run findings, including required manual-review metadata."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", slug):
        raise ValueError(f"Invalid target slug: {slug!r}")

    report_directory = reports_dir / slug
    report_directory.mkdir(parents=True, exist_ok=True)
    report_path = report_directory / "report_json.json"
    records = [
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
    report_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    return report_path