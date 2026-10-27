"""Local duplicate tracking for repeated offline scans."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_REPORTS_DIR = ROOT / "reports"
HISTORY_NAME = "history.json"
DUPLICATE_WINDOW = timedelta(days=14)


def _history_path(reports_dir: Path) -> Path:
    return reports_dir / HISTORY_NAME


def _read_history(reports_dir: Path) -> list[dict[str, object]]:
    history_path = _history_path(reports_dir)
    if not history_path.exists():
        return []
    try:
        records = json.loads(history_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return records if isinstance(records, list) else []


def is_duplicate(
    plugin_slug: str,
    file_name: str,
    line_no: int,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> bool:
    """Return whether the same location was recorded locally within 14 days.

    This deliberately does not contact Patchstack, Wordfence, or any other site.
    """
    cutoff = datetime.now(timezone.utc) - DUPLICATE_WINDOW
    for record in _read_history(reports_dir):
        if (
            record.get("plugin_slug") != plugin_slug
            or record.get("file") != file_name
            or record.get("line") != line_no
        ):
            continue
        try:
            recorded_at = datetime.fromisoformat(str(record["recorded_at"]))
            if recorded_at.tzinfo is None:
                recorded_at = recorded_at.replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            continue
        if recorded_at >= cutoff:
            return True
    return False


def record_finding(
    plugin_slug: str,
    file_name: str,
    line_no: int,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> None:
    """Add or refresh a finding's local observation timestamp."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    records = _read_history(reports_dir)
    records = [
        record
        for record in records
        if not (
            record.get("plugin_slug") == plugin_slug
            and record.get("file") == file_name
            and record.get("line") == line_no
        )
    ]
    records.append(
        {
            "plugin_slug": plugin_slug,
            "file": file_name,
            "line": line_no,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    _history_path(reports_dir).write_text(
        json.dumps(records, indent=2) + "\n", encoding="utf-8"
    )