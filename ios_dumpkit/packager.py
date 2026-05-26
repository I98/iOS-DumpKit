"""Safe IPA packaging using Python zipfile."""

from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .errors import PackagingError, VerificationError


@dataclass(frozen=True, slots=True)
class PackageResult:
    """Result of IPA packaging."""

    path: Path
    sha256: str
    size: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_executable_name(app_bundle: Path) -> str | None:
    info_plist = app_bundle / "Info.plist"
    if not info_plist.exists():
        return None
    with info_plist.open("rb") as handle:
        info = plistlib.load(handle)
    executable = info.get("CFBundleExecutable")
    return str(executable) if executable else None


def _set_executable_permissions(app_bundle: Path) -> None:
    executable_name = _read_executable_name(app_bundle)
    if not executable_name:
        return
    executable = app_bundle / executable_name
    if executable.exists():
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    for binary in [
        *app_bundle.glob("Frameworks/*.framework/*"),
        *app_bundle.glob("PlugIns/*.appex/*"),
    ]:
        if binary.is_file() and not binary.suffix:
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _zipinfo_for(path: Path, arcname: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(arcname)
    info.create_system = 3
    mode = path.lstat().st_mode
    info.external_attr = (mode & 0xFFFF) << 16
    if path.is_dir():
        info.external_attr |= 0x10
    return info


def _write_tree(zip_handle: zipfile.ZipFile, root: Path) -> None:
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs.sort()
        files.sort()
        rel_dir = current_path.relative_to(root).as_posix()
        if rel_dir != ".":
            arc_dir = rel_dir.rstrip("/") + "/"
            zip_handle.writestr(_zipinfo_for(current_path, arc_dir), b"")
        for filename in files:
            path = current_path / filename
            arcname = path.relative_to(root).as_posix()
            info = _zipinfo_for(path, arcname)
            if path.is_symlink():
                zip_handle.writestr(info, os.readlink(path).encode("utf-8"))
            else:
                with path.open("rb") as handle:
                    zip_handle.writestr(info, handle.read(), compress_type=zipfile.ZIP_DEFLATED)


def build_ipa(
    app_bundle: Path, *, output: Path | None = None, output_dir: Path | None = None
) -> PackageResult:
    """Create an IPA containing Payload/AppName.app and return path/hash/size."""

    if not app_bundle.exists() or not app_bundle.is_dir() or app_bundle.suffix != ".app":
        raise PackagingError(f"Expected a local .app bundle, got {app_bundle}")

    if output is not None and output_dir is not None:
        raise PackagingError("Use either --output or --output-dir, not both.")

    output_dir = output_dir or Path.cwd()
    output_dir.mkdir(parents=True, exist_ok=True)
    ipa_path = output if output else output_dir / f"{app_bundle.stem}.ipa"
    if ipa_path.suffix != ".ipa":
        raise PackagingError(f"Output path must end in .ipa: {ipa_path}")
    ipa_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ios-dumpkit-package-") as tmp:
        staging = Path(tmp)
        payload = staging / "Payload"
        staged_app = payload / app_bundle.name
        payload.mkdir()
        shutil.copytree(app_bundle, staged_app, symlinks=True)
        _set_executable_permissions(staged_app)
        with zipfile.ZipFile(ipa_path, "w", compression=zipfile.ZIP_DEFLATED) as zip_handle:
            _write_tree(zip_handle, staging)

    size = ipa_path.stat().st_size
    if size == 0:
        raise VerificationError(f"IPA is empty: {ipa_path}")
    return PackageResult(path=ipa_path, sha256=sha256_file(ipa_path), size=size)
