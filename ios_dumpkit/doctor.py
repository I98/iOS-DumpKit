"""Environment and device diagnostics."""

from __future__ import annotations

import importlib.metadata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .app_resolver import AppResolver
from .config import JAILBREAK_PATHS, ConnectionConfig, SshConfig
from .errors import DumpKitError
from .frida_client import (
    FridaClient,
    assert_frida_compatible,
    get_frida_tools_version,
    get_host_frida_version,
)
from .logging import get_logger
from .ssh_client import SshClient

log = get_logger(__name__)


@dataclass(slots=True)
class DoctorCheck:
    """Single doctor check result."""

    name: str
    ok: bool
    detail: str
    advice: str | None = None


@dataclass(slots=True)
class DoctorReport:
    """Complete doctor result."""

    checks: list[DoctorCheck] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    def add(self, name: str, ok: bool, detail: str, advice: str | None = None) -> None:
        self.checks.append(DoctorCheck(name=name, ok=ok, detail=detail, advice=advice))


def _dependency_version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


class Doctor:
    """Run host, Frida, SSH, app, and filesystem diagnostics."""

    def __init__(self, connection: ConnectionConfig, ssh_config: SshConfig | None = None) -> None:
        self.connection = connection
        self.ssh_config = ssh_config or SshConfig()

    def run(self, *, target: str | None = None, output_dir: Path = Path(".")) -> DoctorReport:
        report = DoctorReport()

        for package in ("frida", "frida-tools", "typer", "rich", "paramiko", "scp", "packaging"):
            version = _dependency_version(package)
            report.add(
                f"Python dependency: {package}",
                version is not None,
                version or "not installed",
                f"Install with: python -m pip install {package}" if version is None else None,
            )

        tools_version = get_frida_tools_version()
        report.add(
            "frida-tools installed", tools_version is not None, tools_version or "not installed"
        )

        try:
            host_version = get_host_frida_version()
            report.add("Host Frida package", True, host_version)
        except DumpKitError as exc:
            report.add("Host Frida package", False, str(exc), "Install frida>=17.")
            host_version = None

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            probe = output_dir / ".ios-dumpkit-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            report.add("Local output directory writeable", True, str(output_dir.resolve()))
        except Exception as exc:
            report.add(
                "Local output directory writeable",
                False,
                str(exc),
                "Choose a writeable --output-dir.",
            )

        frida_client: FridaClient | None = None
        try:
            frida_client = FridaClient(self.connection)
            frida_client.connect()
            remote_version = frida_client.remote_frida_version()
            if host_version:
                assert_frida_compatible(host_version, remote_version)
            report.add(
                "Remote frida-server reachable",
                True,
                remote_version or "reachable; version not exposed",
            )
        except Exception as exc:
            report.add(
                "Remote frida-server reachable",
                False,
                str(exc),
                (
                    "Unlock the device, restart frida-server, prefer USB for validation, "
                    "and check host/port plus version match."
                ),
            )

        apps = []
        if frida_client is not None and frida_client.device is not None:
            try:
                apps = frida_client.enumerate_apps()
                report.add("App enumeration", True, f"{len(apps)} apps visible")
            except Exception as exc:
                report.add(
                    "App enumeration",
                    False,
                    str(exc),
                    (
                        "If remote reachability passed, restart frida-server and try USB; "
                        "some WiFi sessions drop when app metadata is requested."
                    ),
                )

        if target:
            try:
                app = AppResolver(apps).resolve(target).app
                report.add("App installed", True, f"{app.identifier} ({app.name})")
                if app.running:
                    report.add("App can be attached", True, f"running pid {app.pid}")
                else:
                    report.add(
                        "App launch candidate",
                        True,
                        "app is installed but not running; dump can launch unless "
                        "--no-launch is used",
                    )
            except Exception as exc:
                report.add(
                    "App installed", False, str(exc), "Run ios-dumpkit list and use the bundle id."
                )

        if self.ssh_config.enabled:
            self._run_ssh_checks(report)
        else:
            report.add(
                "SSH mode",
                True,
                "not requested; bundle transfer will use Frida RPC fallback",
            )

        return report

    def _run_ssh_checks(self, report: DoctorReport) -> None:
        try:
            with SshClient(self.ssh_config) as ssh:
                report.add(
                    "SSH reachable",
                    True,
                    f"{self.ssh_config.user}@{self.ssh_config.host}:{self.ssh_config.port}",
                )

                for name, command, parser in (
                    ("Device free disk space", "df -Pk /tmp", self._parse_df),
                    ("/tmp writeability", "test -w /tmp", self._parse_zero_exit),
                ):
                    try:
                        result = ssh.run_constant(command)
                        ok, detail = parser(result.exit_status, result.stdout, result.stderr)
                        report.add(name, ok, detail)
                    except Exception as exc:
                        report.add(name, False, str(exc))

                detected = [path for path in JAILBREAK_PATHS if ssh.exists(path)]
                report.add(
                    "Jailbreak layout",
                    bool(detected),
                    ", ".join(detected) if detected else "no common jailbreak paths detected",
                    "Rootless paths often include /var/jb or /private/preboot.",
                )
        except Exception as exc:
            report.add(
                "SSH reachable",
                False,
                str(exc),
                "Check SSH credentials, iproxy port forwarding, or omit SSH to use Frida transfer.",
            )

    @staticmethod
    def _parse_zero_exit(exit_status: int, stdout: str, stderr: str) -> tuple[bool, str]:
        _ = stdout
        if exit_status == 0:
            return True, "ok"
        return False, stderr.strip() or f"exit status {exit_status}"

    @staticmethod
    def _parse_df(exit_status: int, stdout: str, stderr: str) -> tuple[bool, str]:
        if exit_status != 0:
            return False, stderr.strip() or f"exit status {exit_status}"
        lines = [line.split() for line in stdout.splitlines() if line.strip()]
        if len(lines) < 2 or len(lines[1]) < 4:
            return False, stdout.strip() or "df output was empty"
        available_kb = int(lines[1][3])
        detail = f"{available_kb // 1024} MiB available on /tmp"
        return available_kb > 256 * 1024, detail


def report_to_lines(report: DoctorReport, style: Callable[[bool], str] | None = None) -> list[str]:
    """Render report to plain lines for tests or simple output."""

    marker = style or (lambda ok: "OK" if ok else "FAIL")
    return [f"{marker(check.ok)} {check.name}: {check.detail}" for check in report.checks]
