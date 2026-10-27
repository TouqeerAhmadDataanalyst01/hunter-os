"""Offline project-platform identification; this module does not scan for bugs."""

from __future__ import annotations

from pathlib import Path


SUPPORTED_PLATFORMS = ("wordpress", "laravel", "django", "nodejs")
IGNORED_DIRECTORIES = {"vendor", "node_modules", "dist", ".git", "__pycache__"}
PLATFORM_MARKERS = (
    ("wordpress", "wp-config.php"),
    ("laravel", "artisan"),
    ("django", "manage.py"),
    ("nodejs", "package.json"),
)


def _contains_marker(root: Path, marker: str) -> bool:
    for candidate in root.rglob(marker):
        relative = candidate.relative_to(root)
        if candidate.is_file() and not any(
            part.lower() in IGNORED_DIRECTORIES for part in relative.parts[:-1]
        ):
            return True
    return False


def detect_platform(path: str | Path) -> str | None:
    """Detect a platform from its conventional project marker files.

    A PHP-only source tree without a full WordPress project marker is treated as
    a WordPress plugin. Non-WordPress projects require an explicit marker.
    """
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Project directory not found: {root}")

    for platform, marker in PLATFORM_MARKERS:
        if _contains_marker(root, marker):
            return platform

    for php_file in root.rglob("*.php"):
        relative = php_file.relative_to(root)
        if php_file.is_file() and not any(
            part.lower() in IGNORED_DIRECTORIES for part in relative.parts[:-1]
        ):
            return "wordpress"
    return None