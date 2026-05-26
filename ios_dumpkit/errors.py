"""Typed exceptions used across ios-dumpkit-ng."""

from __future__ import annotations


class DumpKitError(Exception):
    """Base class for expected application errors."""

    advice: tuple[str, ...] = ()

    def __init__(self, message: str, *, advice: tuple[str, ...] | None = None) -> None:
        super().__init__(message)
        if advice is not None:
            self.advice = advice


class DependencyError(DumpKitError):
    """A required host dependency is missing or unusable."""


class DeviceConnectionError(DumpKitError):
    """The iOS device or frida-server could not be reached."""


class VersionMismatchError(DumpKitError):
    """Host Frida and remote frida-server are incompatible."""


class TargetResolutionError(DumpKitError):
    """The requested app target could not be resolved unambiguously."""


class AppLifecycleError(DumpKitError):
    """The app could not be launched, attached, or stayed alive."""


class RpcTimeoutError(DumpKitError):
    """A Frida RPC operation exceeded its configured timeout."""


class RpcCallError(DumpKitError):
    """A Frida RPC operation failed."""


class SshError(DumpKitError):
    """SSH or SFTP operations failed."""


class MachOError(DumpKitError):
    """Mach-O parsing or patching failed."""


class PackagingError(DumpKitError):
    """IPA packaging failed."""


class VerificationError(DumpKitError):
    """IPA verification failed."""


DEFAULT_RECOVERY_ADVICE = (
    "Manually open the app and unlock the device.",
    "Use the exact bundle id instead of a display name.",
    "Use USB instead of WiFi when the connection is unstable.",
    "Check that host Frida and frida-server versions match.",
    "Clear the remote temp directory with ios-dumpkit clean.",
    "Increase --timeout for slow devices or large apps.",
)
