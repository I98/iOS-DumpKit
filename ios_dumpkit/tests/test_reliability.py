from __future__ import annotations

import plistlib
import threading
import time
from pathlib import Path

import pytest

from ios_dumpkit.config import DumpOptions
from ios_dumpkit.device import AppInfo, ModuleInfo
from ios_dumpkit.doctor import Doctor
from ios_dumpkit.dumper import IOSDumper
from ios_dumpkit.errors import (
    AppLifecycleError,
    RpcCallError,
    RpcTimeoutError,
    SshError,
    VersionMismatchError,
)
from ios_dumpkit.frida_client import assert_frida_compatible, call_with_timeout_retry


def test_version_comparison_accepts_exact_frida_17() -> None:
    assert_frida_compatible("17.9.8", "17.9.8")


def test_version_comparison_rejects_mismatch() -> None:
    with pytest.raises(VersionMismatchError):
        assert_frida_compatible("17.9.8", "17.8.0")
    with pytest.raises(VersionMismatchError):
        assert_frida_compatible("16.7.0", None)


def test_timeout_wrapper_raises_quickly() -> None:
    started = time.monotonic()

    def slow() -> None:
        time.sleep(1.0)

    with pytest.raises(RpcTimeoutError):
        call_with_timeout_retry(slow, timeout=0.05, retry=0, operation="slow")

    assert time.monotonic() - started < 0.5


def test_retry_wrapper_retries_then_succeeds() -> None:
    calls = {"count": 0}

    def flaky() -> str:
        calls["count"] += 1
        if calls["count"] == 1:
            raise ValueError("not yet")
        return "ok"

    assert call_with_timeout_retry(flaky, timeout=1.0, retry=1, operation="flaky") == "ok"
    assert calls["count"] == 2


def test_mocked_doctor_reports_ssh_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeFridaClient:
        device = object()

        def __init__(self, _connection: object) -> None:
            pass

        def connect(self) -> None:
            return None

        def remote_frida_version(self) -> str:
            return "17.9.8"

        def enumerate_apps(self) -> list:
            return []

    class FakeSshClient:
        def __init__(self, _config: object) -> None:
            raise SshError("auth failed")

    monkeypatch.setattr("ios_dumpkit.doctor.FridaClient", FakeFridaClient)
    monkeypatch.setattr("ios_dumpkit.doctor.get_host_frida_version", lambda: "17.9.8")
    monkeypatch.setattr("ios_dumpkit.doctor.SshClient", FakeSshClient)

    report = Doctor(
        connection=object(),  # type: ignore[arg-type]
        ssh_config=type(
            "Cfg", (), {"enabled": True, "host": "127.0.0.1", "port": 2222, "user": "root"}
        )(),
    ).run(output_dir=tmp_path)

    assert any(check.name == "SSH reachable" and not check.ok for check in report.checks)


def test_remote_temp_missing_raises_rpc_error(tmp_path: Path) -> None:
    class FakeRpc:
        def call(self, method: str, *_args: object, **_kwargs: object) -> dict:
            if method == "statpath":
                return {"exists": False}
            raise AssertionError(method)

    dumper = IOSDumper(connection=object())  # type: ignore[arg-type]
    with pytest.raises(RpcCallError):
        dumper._download_file_via_frida(
            FakeRpc(),  # type: ignore[arg-type]
            "/tmp/missing",
            tmp_path / "missing",
            DumpOptions(timeout=0.1),
        )


def test_mocked_app_crash_during_dump_raises_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle_path = "/private/var/containers/Bundle/Application/UUID/Crash.app"
    info = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.example.crash",
            "CFBundleExecutable": "Crash",
        }
    )
    files = {
        f"{bundle_path}/Info.plist": info,
        f"{bundle_path}/Crash": b"\xcf\xfa\xed\xfe" + (b"\x00" * 512),
    }

    class FakeExports:
        def getbundleinfo(self) -> dict:
            return {
                "bundleId": "com.example.crash",
                "appName": "Crash.app",
                "bundlePath": bundle_path,
                "executablePath": f"{bundle_path}/Crash",
                "executableName": "Crash",
            }

        def enumeratemodules(self) -> list[dict]:
            return [
                {
                    "name": "Crash",
                    "path": f"{bundle_path}/Crash",
                    "base": "0x100000000",
                    "size": 512,
                    "isAppModule": True,
                    "isMain": True,
                    "isFramework": False,
                    "isExtension": False,
                    "encrypted": True,
                    "relativePath": "Crash",
                    "encryption": {
                        "cryptoff": 256,
                        "cryptsize": 32,
                        "cryptid": 1,
                        "cryptidFileOffset": 64,
                    },
                }
            ]

        def listfiles(self, _root: str) -> dict:
            return {"dirs": [], "files": ["Info.plist", "Crash"]}

        def statpath(self, path: str) -> dict:
            return {"exists": True, "isDir": False, "size": len(files[path])}

        def readfile(self, path: str, offset: int, size: int) -> bytes:
            return files[path][offset : offset + size]

        def ensuredir(self, _path: str) -> bool:
            return True

    class FakeScript:
        exports_sync = FakeExports()

        def unload(self) -> None:
            return None

    class FakeSessionObject:
        def detach(self) -> None:
            return None

    class FakeFridaSession:
        script = FakeScript()
        session = FakeSessionObject()
        pid = 123
        detached = threading.Event()

        def __init__(self) -> None:
            self.detached.set()

    class FakeFridaClient:
        def connect(self) -> object:
            return object()

        def enumerate_apps(self) -> list[AppInfo]:
            return [AppInfo(identifier="com.example.crash", name="Crash", pid=123)]

        def attach_or_launch(self, *_args: object, **_kwargs: object) -> FakeFridaSession:
            return FakeFridaSession()

        def modules_from_payload(self, _payload: object) -> list[ModuleInfo]:
            return [
                ModuleInfo(
                    name="Crash",
                    path=f"{bundle_path}/Crash",
                    base="0x100000000",
                    size=512,
                    is_app_module=True,
                    is_main=True,
                    is_framework=False,
                    is_extension=False,
                    encrypted=True,
                    relative_path="Crash",
                )
            ]

    dumper = IOSDumper(connection=object())  # type: ignore[arg-type]
    dumper.frida_client = FakeFridaClient()  # type: ignore[assignment]

    with pytest.raises(AppLifecycleError) as exc:
        dumper.dump("com.example.crash", DumpOptions(output_dir=tmp_path, timeout=0.1))

    assert "App exited during dump" in str(exc.value)
