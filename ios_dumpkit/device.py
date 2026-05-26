"""Structured models for devices, apps, bundles, and modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """Frida device identity and system parameters."""

    id: str
    name: str
    type: str
    os: str | None = None
    arch: str | None = None
    frida_server_version: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AppInfo:
    """Installed iOS app metadata."""

    identifier: str
    name: str
    pid: int = 0
    executable: str | None = None
    bundle_path: str | None = None
    version: str | None = None
    build: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)

    @property
    def running(self) -> bool:
        return self.pid != 0

    @property
    def app_dirname(self) -> str:
        if self.bundle_path:
            return PurePosixPath(self.bundle_path).name
        safe = self.name.strip() or self.identifier
        return f"{safe}.app" if not safe.endswith(".app") else safe


@dataclass(frozen=True, slots=True)
class BundleInfo:
    """Bundle information returned by the Frida agent."""

    bundle_id: str
    app_name: str
    bundle_path: str
    executable_path: str
    executable_name: str
    data_container: str | None = None
    group_containers: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class EncryptionInfo:
    """Encryption load-command data for a Mach-O image."""

    cryptoff: int
    cryptsize: int
    cryptid: int
    cryptid_file_offset: int


@dataclass(frozen=True, slots=True)
class ModuleInfo:
    """Runtime module metadata returned by the Frida agent."""

    name: str
    path: str
    base: str
    size: int
    is_app_module: bool
    is_main: bool
    is_framework: bool
    is_extension: bool
    encrypted: bool
    encryption: EncryptionInfo | None = None
    macho_type: str | None = None
    relative_path: str | None = None


@dataclass(frozen=True, slots=True)
class JailbreakInfo:
    """Detected jailbreak filesystem layout hints."""

    detected_paths: list[str]
    rootless: bool


def app_from_frida(application: Any) -> AppInfo:
    """Convert a Frida Application object into an AppInfo dataclass."""

    params = dict(getattr(application, "parameters", None) or {})
    identifier = str(getattr(application, "identifier", params.get("identifier", "")))
    name = str(getattr(application, "name", params.get("name", identifier)))
    pid = int(getattr(application, "pid", params.get("pid", 0)) or 0)
    executable = (
        params.get("executable")
        or params.get("CFBundleExecutable")
        or params.get("binary")
        or params.get("executableName")
    )
    bundle_path = params.get("path") or params.get("bundlePath") or params.get("bundle")
    version = params.get("version") or params.get("CFBundleShortVersionString")
    build = params.get("build") or params.get("CFBundleVersion")
    return AppInfo(
        identifier=identifier,
        name=name,
        pid=pid,
        executable=str(executable) if executable else None,
        bundle_path=str(bundle_path) if bundle_path else None,
        version=str(version) if version else None,
        build=str(build) if build else None,
        parameters=params,
    )


def bundle_info_from_agent(payload: dict[str, Any]) -> BundleInfo:
    """Convert the Frida agent bundle info schema into BundleInfo."""

    return BundleInfo(
        bundle_id=str(payload.get("bundleId") or payload.get("bundle_id") or ""),
        app_name=str(payload.get("appName") or payload.get("app_name") or ""),
        bundle_path=str(payload.get("bundlePath") or payload.get("bundle_path") or ""),
        executable_path=str(payload.get("executablePath") or payload.get("executable_path") or ""),
        executable_name=str(payload.get("executableName") or payload.get("executable_name") or ""),
        data_container=payload.get("dataContainer") or payload.get("data_container"),
        group_containers=list(
            payload.get("groupContainers") or payload.get("group_containers") or []
        ),
    )


def module_info_from_agent(payload: dict[str, Any]) -> ModuleInfo:
    """Convert the Frida agent module schema into ModuleInfo."""

    enc_payload = payload.get("encryption")
    encryption = None
    if isinstance(enc_payload, dict):
        encryption = EncryptionInfo(
            cryptoff=int(enc_payload.get("cryptoff", 0)),
            cryptsize=int(enc_payload.get("cryptsize", 0)),
            cryptid=int(enc_payload.get("cryptid", 0)),
            cryptid_file_offset=int(enc_payload.get("cryptidFileOffset", 0)),
        )
    return ModuleInfo(
        name=str(payload.get("name") or ""),
        path=str(payload.get("path") or ""),
        base=str(payload.get("base") or ""),
        size=int(payload.get("size") or 0),
        is_app_module=bool(payload.get("isAppModule", False)),
        is_main=bool(payload.get("isMain", False)),
        is_framework=bool(payload.get("isFramework", False)),
        is_extension=bool(payload.get("isExtension", False)),
        encrypted=bool(payload.get("encrypted", False)),
        encryption=encryption,
        macho_type=payload.get("machoType"),
        relative_path=payload.get("relativePath"),
    )
