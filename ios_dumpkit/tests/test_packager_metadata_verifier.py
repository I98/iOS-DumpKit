from __future__ import annotations

import json
import zipfile
from pathlib import Path

from ios_dumpkit.metadata import write_metadata
from ios_dumpkit.packager import build_ipa
from ios_dumpkit.verifier import verify_ipa


def test_packager_builds_valid_payload_structure(app_bundle: Path, tmp_path: Path) -> None:
    result = build_ipa(app_bundle, output_dir=tmp_path)

    assert result.path.exists()
    assert len(result.sha256) == 64
    with zipfile.ZipFile(result.path) as zf:
        assert "Payload/Example App.app/Info.plist" in zf.namelist()
        assert "Payload/Example App.app/Example" in zf.namelist()
    assert verify_ipa(result.path).valid


def test_metadata_json_generation(app_bundle: Path, tmp_path: Path) -> None:
    metadata = write_metadata(app_bundle, tmp_path)
    payload = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))

    assert metadata.bundle_id == "com.example.app"
    assert payload["url_schemes"] == ["example", "example-auth"]
    assert payload["keychain_access_groups"] == ["TEAM.com.example.app"]
    assert payload["associated_domains"] == ["applinks:example.com"]
    assert (tmp_path / "Info.plist").exists()
    assert (tmp_path / "entitlements.plist").exists()


def test_verifier_reports_missing_payload(tmp_path: Path) -> None:
    bad = tmp_path / "bad.ipa"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("NotPayload/file.txt", "bad")

    result = verify_ipa(bad)

    assert not result.valid
    assert any("Payload" in error for error in result.errors)
