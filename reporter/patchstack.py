"""Write local Markdown review notes with a Patchstack-style section layout."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORTS_DIR = ROOT / "reports"


def _safe_slug(slug: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", slug):
        raise ValueError(f"Invalid plugin slug: {slug!r}")
    return slug


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