"""Safely extract a plugin ZIP that is already present in the workspace."""

from __future__ import annotations

import re
import shutil
import stat
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Optional


ROOT = Path(__file__).resolve().parent.parent
LOCAL_ARCHIVES = ROOT / "targets" / "archives"
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_MEMBER_BYTES = 20 * 1024 * 1024
MAX_TOTAL_EXPANDED_BYTES = 200 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000


def _validate_slug(slug: str) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", slug):
        raise ValueError(f"Invalid plugin slug: {slug!r}")


def _is_directory_member(member: zipfile.ZipInfo) -> bool:
    mode = (member.external_attr >> 16) & 0xFFFF
    return (
        member.is_dir()
        or member.filename.endswith(("/", "\\"))
        or stat.S_ISDIR(mode)
    )


def _extract_archive(archive_path: Path, destination: Path) -> Path:
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"Local archive exceeds {MAX_ARCHIVE_BYTES} bytes: {archive_path}")

    if destination.is_symlink():
        raise ValueError(f"Refusing a symbolic-link extraction path: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError(f"Extraction destination must be a new empty directory: {destination}")
    destination_resolved = destination.resolve()

    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError(
                f"Archive contains more than {MAX_ARCHIVE_MEMBERS} members: {archive_path}"
            )

        expanded_bytes = 0
        seen_paths: set[str] = set()
        for member in members:
            if member.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"Archive member is too large: {member.filename}")
            expanded_bytes += member.file_size
            if expanded_bytes > MAX_TOTAL_EXPANDED_BYTES:
                raise ValueError(
                    "Archive expands beyond "
                    f"{MAX_TOTAL_EXPANDED_BYTES} bytes: {archive_path}"
                )

            raw_name = member.filename
            if "\x00" in raw_name:
                raise ValueError(f"Unsafe path in archive: {raw_name}")
            normalized_name = raw_name.replace("\\", "/")
            posix_name = PurePosixPath(normalized_name)
            windows_name = PureWindowsPath(raw_name)
            if (
                posix_name.is_absolute()
                or windows_name.is_absolute()
                or windows_name.drive
                or any(part == ".." for part in posix_name.parts)
            ):
                raise ValueError(f"Unsafe path in archive: {raw_name}")

            canonical_name = posix_name.as_posix().rstrip("/").casefold()
            if not canonical_name or canonical_name in seen_paths:
                raise ValueError(f"Duplicate or empty path in archive: {raw_name}")
            seen_paths.add(canonical_name)

            mode = (member.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if stat.S_ISLNK(mode):
                raise ValueError(f"Symbolic links are not allowed: {raw_name}")
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError(f"Special files are not allowed: {raw_name}")
            if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError(f"Unsupported compression method: {raw_name}")

            member_path = (destination / Path(*posix_name.parts)).resolve()
            if member_path != destination_resolved and destination_resolved not in member_path.parents:
                raise ValueError(f"Unsafe path in archive: {raw_name}")
        actual_expanded_bytes = 0
        try:
            for member in members:
                relative_member = Path(
                    *PurePosixPath(member.filename.replace("\\", "/")).parts
                )
                member_path = destination / relative_member
                if _is_directory_member(member):
                    if member.file_size != 0:
                        raise ValueError(
                            f"Directory member contains data: {member.filename}"
                        )
                    member_path.mkdir(parents=True, exist_ok=True)
                    continue
                member_path.parent.mkdir(parents=True, exist_ok=True)
                member_expanded_bytes = 0
                with archive.open(member) as source, member_path.open("xb") as output:
                    while chunk := source.read(64 * 1024):
                        member_expanded_bytes += len(chunk)
                        actual_expanded_bytes += len(chunk)
                        if member_expanded_bytes > MAX_MEMBER_BYTES:
                            raise ValueError(
                                f"Archive member is too large: {member.filename}"
                            )
                        if actual_expanded_bytes > MAX_TOTAL_EXPANDED_BYTES:
                            raise ValueError(
                                "Archive expands beyond "
                                f"{MAX_TOTAL_EXPANDED_BYTES} bytes: {archive_path}"
                            )
                        output.write(chunk)
                if member_expanded_bytes != member.file_size:
                    raise ValueError(
                        f"Invalid expanded size for archive member: {member.filename}"
                    )
        except (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError) as error:
            raise ValueError(f"Could not safely extract local archive: {error}") from error

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
    try:
        return _extract_archive(archive_path, destination)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        shutil.rmtree(destination)
        raise


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
        extract_root.mkdir(parents=True, exist_ok=True)
        destination = Path(tempfile.mkdtemp(prefix=f"{slug}-", dir=extract_root))
        try:
            source_root = _extract_archive(archive_path, destination)
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
            shutil.rmtree(destination)
            raise
        print(f"[extract] Extracted local archive to: {destination}")
        return source_root

    print(
        f"Download https://downloads.wordpress.org/plugin/{slug}.zip to "
        f"targets/archives/{slug}.zip manually"
    )
    return None