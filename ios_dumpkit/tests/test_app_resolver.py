from __future__ import annotations

import pytest

from ios_dumpkit.app_resolver import AppResolver
from ios_dumpkit.device import AppInfo
from ios_dumpkit.errors import TargetResolutionError


def test_resolves_bundle_display_and_executable_names() -> None:
    apps = [
        AppInfo(identifier="com.example.safe", name="Example App", executable="Example"),
        AppInfo(identifier="com.example.unicode", name="Café Test", executable="CafeExec"),
    ]
    resolver = AppResolver(apps)

    assert resolver.resolve("com.example.safe").app.identifier == "com.example.safe"
    assert resolver.resolve("Example App").matched_by == "display-name"
    assert resolver.resolve("CafeExec").matched_by == "executable"
    assert resolver.resolve("cafe test").app.identifier == "com.example.unicode"


def test_unsafe_display_name_is_never_interpreted_as_shell() -> None:
    unsafe_name = "Bob's Bank; rm -rf / $(touch nope)"
    app = AppInfo(identifier="com.example.bank", name=unsafe_name, executable="Bank")
    resolved = AppResolver([app]).resolve(unsafe_name)

    assert resolved.app.identifier == "com.example.bank"
    assert resolved.query == unsafe_name


def test_duplicate_display_names_require_bundle_id() -> None:
    apps = [
        AppInfo(identifier="com.example.one", name="Example App"),
        AppInfo(identifier="com.example.two", name="Example App"),
    ]
    with pytest.raises(TargetResolutionError) as exc:
        AppResolver(apps).resolve("Example App")

    assert "matched multiple apps" in str(exc.value)
    assert "com.example.one" in "\n".join(exc.value.advice)


def test_app_not_found_is_actionable() -> None:
    with pytest.raises(TargetResolutionError) as exc:
        AppResolver([AppInfo(identifier="com.example.app", name="Example")]).resolve("Missing App")

    assert "No installed app matched" in str(exc.value)
    assert "ios-dumpkit list" in "\n".join(exc.value.advice)
