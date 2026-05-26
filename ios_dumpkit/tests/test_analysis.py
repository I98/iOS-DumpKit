from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from ios_dumpkit.analysis import (
    _run_optional_tool,
    write_objc_runtime_artifacts,
    write_static_analysis_artifacts,
)


def test_static_analysis_artifacts_are_written(app_bundle: Path, tmp_path: Path) -> None:
    artifacts = write_static_analysis_artifacts(app_bundle, tmp_path)

    assert artifacts
    assert (tmp_path / "analysis" / "manifest.json").exists()
    manifest = json.loads((tmp_path / "analysis" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest[0]["relative_path"] == "Example"
    assert (tmp_path / "analysis" / "macho" / "Example.macho.json").exists()
    assert (tmp_path / "analysis" / "strings" / "Example.strings.txt").exists()


def test_objc_runtime_headers_are_written(tmp_path: Path) -> None:
    count = write_objc_runtime_artifacts(
        {
            "available": True,
            "classes": [
                {
                    "name": "ExampleViewController",
                    "superclass": "UIViewController",
                    "protocols": ["UITableViewDelegate"],
                    "methods": ["- viewDidLoad", "+ sharedInstance"],
                }
            ],
        },
        tmp_path,
    )

    header = tmp_path / "analysis" / "objc" / "headers" / "ExampleViewController.h"
    assert count == 1
    assert header.exists()
    assert (
        "@interface ExampleViewController : UIViewController <UITableViewDelegate>"
        in header.read_text(encoding="utf-8")
    )


def test_failed_optional_tool_does_not_write_error_file(monkeypatch, tmp_path: Path) -> None:
    destination = tmp_path / "bad.disasm.txt"

    monkeypatch.setattr("ios_dumpkit.analysis.shutil.which", lambda _tool: "/usr/bin/tool")
    monkeypatch.setattr(
        "ios_dumpkit.analysis.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="ERROR: Missing bin header addrline",
        ),
    )

    assert not _run_optional_tool(["rabin2", "-d", "binary"], destination)
    assert not destination.exists()
