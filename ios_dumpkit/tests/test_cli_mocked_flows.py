from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from ios_dumpkit.cli import app
from ios_dumpkit.device import AppInfo
from ios_dumpkit.doctor import DoctorReport

runner = CliRunner()


def test_cli_list_mocked_flow(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class FakeFridaClient:
        def __init__(self, _connection: object) -> None:
            pass

        def connect(self) -> object:
            return object()

        def enumerate_apps(self) -> list[AppInfo]:
            return [AppInfo(identifier="com.example.app", name="Example App", executable="Example")]

    monkeypatch.setattr("ios_dumpkit.cli.FridaClient", FakeFridaClient)

    result = runner.invoke(app, ["list", "--usb"])

    assert result.exit_code == 0
    assert "com.example.app" in result.output


def test_cli_doctor_mocked_flow(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    class FakeDoctor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, *_args: object, **_kwargs: object) -> DoctorReport:
            report = DoctorReport()
            report.add("mock check", True, "ok")
            return report

    monkeypatch.setattr("ios_dumpkit.cli.Doctor", FakeDoctor)

    result = runner.invoke(app, ["doctor", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "mock check" in result.output


def test_cli_dump_mocked_flow(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    class FakeDumper:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def dump(self, _target: str, _options: object) -> object:
            return SimpleNamespace(
                bundle=SimpleNamespace(bundle_id="com.example.app"),
                metadata_dir=tmp_path / "metadata",
                package=SimpleNamespace(path=tmp_path / "Example.ipa", sha256="a" * 64),
                dumped_modules=[object()],
                work_dir=None,
            )

    monkeypatch.setattr("ios_dumpkit.cli.IOSDumper", FakeDumper)

    result = runner.invoke(app, ["dump", "com.example.app", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "com.example.app" in result.output
    assert "Example.ipa" in result.output
