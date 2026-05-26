"""Metadata extraction and JSON emission."""

from __future__ import annotations

import json
import plistlib
import re
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .macho import MachOError, analyse_file

PLIST_RE = re.compile(rb"(<\?xml[^<]*.*?</plist>)", re.DOTALL)


@dataclass(slots=True)
class AppMetadata:
    """Serializable app metadata summary."""

    bundle_id: str | None
    app_version: str | None
    build_number: str | None
    minimum_ios_version: str | None
    executable_name: str | None
    url_schemes: list[str] = field(default_factory=list)
    ats_settings: dict[str, Any] = field(default_factory=dict)
    keychain_access_groups: list[str] = field(default_factory=list)
    associated_domains: list[str] = field(default_factory=list)
    app_groups: list[str] = field(default_factory=list)
    imported_dylibs: list[str] = field(default_factory=list)
    exported_dylibs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def read_info_plist(bundle_path: Path) -> dict[str, Any]:
    plist_path = bundle_path / "Info.plist"
    if not plist_path.exists():
        raise FileNotFoundError(f"Info.plist not found under {bundle_path}")
    with plist_path.open("rb") as handle:
        payload = plistlib.load(handle)
    return dict(payload)


def _url_schemes(info: dict[str, Any]) -> list[str]:
    schemes: list[str] = []
    for entry in info.get("CFBundleURLTypes", []) or []:
        if isinstance(entry, dict):
            for scheme in entry.get("CFBundleURLSchemes", []) or []:
                schemes.append(str(scheme))
    return sorted(set(schemes))


def extract_entitlements(binary_path: Path) -> dict[str, Any]:
    """Best-effort extraction of XML plist entitlements embedded in a Mach-O."""

    data = binary_path.read_bytes()
    candidates = PLIST_RE.findall(data)
    for candidate in candidates:
        if b"com.apple.developer" not in candidate and b"keychain-access-groups" not in candidate:
            continue
        try:
            decoded = plistlib.loads(candidate)
        except Exception:
            continue
        if isinstance(decoded, dict):
            return dict(decoded)
    return {}


def _binary_paths(bundle_path: Path, executable_name: str | None) -> list[Path]:
    candidates: list[Path] = []
    if executable_name:
        candidates.append(bundle_path / executable_name)
    for path in bundle_path.rglob("*"):
        if path.is_file() and path not in candidates:
            try:
                magic = path.read_bytes()[:4]
            except OSError:
                continue
            if magic in {
                b"\xcf\xfa\xed\xfe",
                b"\xce\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe",
                b"\xca\xfe\xba\xbf",
            }:
                candidates.append(path)
    return candidates


def collect_metadata(bundle_path: Path) -> tuple[AppMetadata, dict[str, Any], dict[str, Any]]:
    """Collect Info.plist, entitlements, and dylib metadata from a local app bundle."""

    info = read_info_plist(bundle_path)
    executable_name = info.get("CFBundleExecutable")
    main_binary = bundle_path / str(executable_name) if executable_name else None
    entitlements = extract_entitlements(main_binary) if main_binary and main_binary.exists() else {}

    imported: set[str] = set()
    exported: set[str] = set()
    for binary in _binary_paths(bundle_path, str(executable_name) if executable_name else None):
        try:
            analysis = analyse_file(binary)
        except (MachOError, OSError):
            continue
        imported.update(analysis.imported_dylibs)
        exported.update(analysis.exported_dylibs)

    metadata = AppMetadata(
        bundle_id=info.get("CFBundleIdentifier"),
        app_version=info.get("CFBundleShortVersionString"),
        build_number=info.get("CFBundleVersion"),
        minimum_ios_version=info.get("MinimumOSVersion"),
        executable_name=str(executable_name) if executable_name else None,
        url_schemes=_url_schemes(info),
        ats_settings=dict(info.get("NSAppTransportSecurity") or {}),
        keychain_access_groups=list(entitlements.get("keychain-access-groups") or []),
        associated_domains=list(entitlements.get("com.apple.developer.associated-domains") or []),
        app_groups=list(entitlements.get("com.apple.security.application-groups") or []),
        imported_dylibs=sorted(imported),
        exported_dylibs=sorted(exported),
    )
    return metadata, info, entitlements


def write_metadata(bundle_path: Path, output_dir: Path) -> AppMetadata:
    """Write metadata.json, entitlements.plist, Info.plist copy, and mobileprovision copy."""

    output_dir.mkdir(parents=True, exist_ok=True)
    metadata, _info, entitlements = collect_metadata(bundle_path)

    (output_dir / "metadata.json").write_text(
        json.dumps(metadata.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    info_src = bundle_path / "Info.plist"
    if info_src.exists():
        shutil.copy2(info_src, output_dir / "Info.plist")

    if entitlements:
        with (output_dir / "entitlements.plist").open("wb") as handle:
            plistlib.dump(entitlements, handle)

    provision = bundle_path / "embedded.mobileprovision"
    if provision.exists():
        shutil.copy2(provision, output_dir / "embedded.mobileprovision")

    return metadata
