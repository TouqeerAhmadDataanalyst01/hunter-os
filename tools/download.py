"""Safely extract a plugin ZIP that is already present in the workspace."""

from __future__ import annotations

import re
import tempfile
import zipfile
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parent.parent
LOCAL_ARCHIVES = ROOT / "targets" / "archives"
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_MEMBER_BYTES = 20 * 1024 * 1024


def _validate_slug(slug: str) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", slug):
        raise ValueError(f"Invalid plugin slug: {slug!r}")


def _extract_archive(archive_path: Path, destination: Path) -> Path:
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"Local archive exceeds {MAX_ARCHIVE_BYTES} bytes: {archive_path}")

    destination.mkdir(parents=True, exist_ok=True)
    destination_resolved = destination.resolve()

    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            if member.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"Archive member is too large: {member.filename}")
            member_path = (destination / member.filename).resolve()
            if member_path != destination_resolved and destination_resolved not in member_path.parents:
                raise ValueError(f"Unsafe path in archive: {member.filename}")
            if member.external_attr >> 28 == 0xA:
                raise ValueError(f"Symbolic links are not allowed: {member.filename}")
        archive.extractall(destination)

    return _source_root(destination)


def _source_root(destination: Path) -> Path:
    children = list(destination.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return destination


def download_plugin(slug: str, archives_dir: Path = LOCAL_ARCHIVES) -> Path:
    """Extract `targets/archives/<slug>.zip` to a temporary directory, offline."""
    _validate_slug(slug)
    archive_path = archives_dir / f"{slug}.zip"
    if not archive_path.is_file():
        raise FileNotFoundError(
            f"No local source at targets/plugins/{slug} and no local archive at "
            f"targets/archives/{slug}.zip"
        )
    destination = Path(tempfile.mkdtemp(prefix=f"hunter-os-{slug}-"))
    return _extract_archive(archive_path, destination)


def get_plugin_local_or_instructions(
    slug: str,
    plugins_dir: Path = ROOT / "targets" / "plugins",
    archives_dir: Path = LOCAL_ARCHIVES,
    extract_root: Path = Path(tempfile.gettempdir()) / "plugins",
) -> Optional[Path]:
    """Resolve local plugin source or print instructions; never access a network."""
    _validate_slug(slug)

    plugin_path = plugins_dir / slug
    if plugin_path.is_dir():
        print(f"[source] Using local plugin directory: {plugin_path}")
        return plugin_path

    archive_path = archives_dir / f"{slug}.zip"
    if archive_path.is_file():
        destination = extract_root / slug
        if destination.is_symlink():
            raise ValueError(f"Refusing symlink extraction path: {destination}")
        if destination.is_dir():
            print(f"[source] Using previously extracted local archive: {destination}")
            return destination
        _extract_archive(archive_path, destination)
        print(f"[extract] Extracted local archive to: {destination}")
        return destination

    print(
        f"Download https://downloads.wordpress.org/plugin/{slug}.zip to "
        f"targets/archives/{slug}.zip manually"
    )
    return None