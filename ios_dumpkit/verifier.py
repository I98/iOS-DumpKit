"""IPA verification helpers."""

from __future__ import annotations

import plistlib
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .macho import MachOError, parse_macho


@dataclass(slots=True)
class VerificationResult:
    """Verification outcome."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    app_bundle: str | None = None
    encrypted_binaries: list[str] = field(default_factory=list)


def _zip_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0xFFFF


def verify_ipa(path: Path) -> VerificationResult:
    """Verify Payload/App.app structure and flag encrypted Mach-O binaries."""

    errors: list[str] = []
    warnings: list[str] = []
    encrypted: list[str] = []
    app_bundle: str | None = None

    if not path.exists():
        return VerificationResult(valid=False, errors=[f"File does not exist: {path}"])
    if path.suffix != ".ipa":
        errors.append("File extension is not .ipa.")

    try:
        with zipfile.ZipFile(path) as zip_handle:
            names = zip_handle.namelist()
            app_roots = sorted(
                {
                    "/".join(name.split("/")[:2])
                    for name in names
                    if name.startswith("Payload/")
                    and len(name.split("/")) >= 2
                    and name.split("/")[1].endswith(".app")
                }
            )
            if len(app_roots) != 1:
                errors.append(
                    f"Expected exactly one Payload/*.app directory, found {len(app_roots)}."
                )
            else:
                app_bundle = app_roots[0]
                info_name = f"{app_bundle}/Info.plist"
                if info_name not in names:
                    errors.append("Missing Payload app Info.plist.")
                else:
                    info_data = zip_handle.read(info_name)
                    try:
                        info = plistlib.loads(info_data)
                    except Exception as exc:
                        errors.append(f"Info.plist could not be parsed: {exc}")
                        info = {}
                    executable = info.get("CFBundleExecutable") if isinstance(info, dict) else None
                    if executable:
                        executable_name = f"{app_bundle}/{executable}"
                        if executable_name not in names:
                            errors.append(f"Missing main executable: {executable_name}")
                        else:
                            mode = _zip_mode(zip_handle.getinfo(executable_name))
                            if not mode & stat.S_IXUSR:
                                warnings.append(
                                    "Main executable is not marked executable in ZIP metadata."
                                )
                    else:
                        errors.append("CFBundleExecutable is missing from Info.plist.")

            for name in names:
                if name.endswith("/"):
                    continue
                data = zip_handle.read(name)
                if data[:4] not in {
                    b"\xcf\xfa\xed\xfe",
                    b"\xce\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe",
                    b"\xca\xfe\xba\xbf",
                }:
                    continue
                try:
                    analysis = parse_macho(data)
                except MachOError as exc:
                    warnings.append(f"Unable to parse Mach-O {name}: {exc}")
                    continue
                if analysis.encrypted:
                    encrypted.append(name)
            if encrypted:
                errors.append(f"{len(encrypted)} Mach-O file(s) still have cryptid != 0.")
    except zipfile.BadZipFile as exc:
        errors.append(f"Not a valid ZIP/IPA: {exc}")

    return VerificationResult(
        valid=not errors,
        errors=errors,
        warnings=warnings,
        app_bundle=app_bundle,
        encrypted_binaries=encrypted,
    )
