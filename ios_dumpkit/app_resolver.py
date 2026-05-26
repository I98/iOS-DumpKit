"""Target resolution for bundle ids, display names, and executable names."""

from __future__ import annotations

from dataclasses import dataclass
from unicodedata import combining, normalize

from .device import AppInfo
from .errors import TargetResolutionError


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """Resolved app target."""

    app: AppInfo
    matched_by: str
    query: str


def _norm(value: str | None) -> str:
    if not value:
        return ""
    decomposed = normalize("NFKD", value)
    without_marks = "".join(char for char in decomposed if not combining(char))
    return normalize("NFKC", without_marks).casefold().strip()


def _candidate_lines(apps: list[AppInfo]) -> tuple[str, ...]:
    return tuple(f"{app.identifier}  {app.name}  pid={app.pid or '-'}" for app in apps)


class AppResolver:
    """Resolve user input to a unique bundle id without shell-sensitive handling."""

    def __init__(self, apps: list[AppInfo]) -> None:
        self.apps = apps

    def list_apps(self, query: str | None = None) -> list[AppInfo]:
        if not query:
            return sorted(
                self.apps, key=lambda app: (app.pid == 0, _norm(app.name), app.identifier)
            )
        needle = _norm(query)
        matches = [
            app
            for app in self.apps
            if needle in _norm(app.identifier)
            or needle in _norm(app.name)
            or needle in _norm(app.executable)
        ]
        return sorted(matches, key=lambda app: (app.pid == 0, _norm(app.name), app.identifier))

    def resolve(self, query: str) -> ResolvedTarget:
        if not query or not query.strip():
            raise TargetResolutionError("Target cannot be empty.")

        raw_query = query.strip()
        norm_query = _norm(raw_query)

        bundle_matches = [app for app in self.apps if app.identifier == raw_query]
        if len(bundle_matches) == 1:
            return ResolvedTarget(bundle_matches[0], "bundle-id", raw_query)

        executable_matches = [app for app in self.apps if _norm(app.executable) == norm_query]
        if len(executable_matches) == 1:
            return ResolvedTarget(executable_matches[0], "executable", raw_query)
        if len(executable_matches) > 1:
            raise TargetResolutionError(
                f'Executable name "{raw_query}" matched multiple apps. Use an exact bundle id.',
                advice=_candidate_lines(executable_matches),
            )

        display_matches = [app for app in self.apps if _norm(app.name) == norm_query]
        if len(display_matches) == 1:
            return ResolvedTarget(display_matches[0], "display-name", raw_query)
        if len(display_matches) > 1:
            raise TargetResolutionError(
                f'Display name "{raw_query}" matched multiple apps. Use an exact bundle id.',
                advice=_candidate_lines(display_matches),
            )

        fuzzy_matches = [
            app
            for app in self.apps
            if norm_query in _norm(app.name)
            or norm_query in _norm(app.identifier)
            or norm_query in _norm(app.executable)
        ]
        if len(fuzzy_matches) == 1:
            return ResolvedTarget(fuzzy_matches[0], "search", raw_query)
        if len(fuzzy_matches) > 1:
            raise TargetResolutionError(
                f'"{raw_query}" matched multiple apps. Use an exact bundle id.',
                advice=_candidate_lines(fuzzy_matches),
            )

        raise TargetResolutionError(
            f'No installed app matched "{raw_query}".',
            advice=(
                "Run ios-dumpkit list and use the exact bundle id.",
                "Display names with spaces, apostrophes, or unicode are supported, "
                "but must match uniquely.",
            ),
        )
