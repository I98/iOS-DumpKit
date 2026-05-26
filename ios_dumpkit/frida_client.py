"""Modern Frida client wrapper with version checks, timeouts, and retries."""

from __future__ import annotations

import importlib.metadata
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.version import Version

from .config import ConnectionConfig
from .device import AppInfo, DeviceInfo, app_from_frida, module_info_from_agent
from .errors import (
    DEFAULT_RECOVERY_ADVICE,
    AppLifecycleError,
    DependencyError,
    DeviceConnectionError,
    RpcCallError,
    RpcTimeoutError,
    VersionMismatchError,
)
from .logging import get_logger

log = get_logger(__name__)


def _import_frida() -> Any:
    try:
        import frida  # type: ignore[import-not-found]
    except Exception as exc:
        raise DependencyError("Python package 'frida' is not installed.") from exc
    return frida


def get_host_frida_version() -> str:
    frida = _import_frida()
    return str(getattr(frida, "__version__", importlib.metadata.version("frida")))


def get_frida_tools_version() -> str | None:
    try:
        return importlib.metadata.version("frida-tools")
    except importlib.metadata.PackageNotFoundError:
        return None


def _normalise_version(value: str) -> Version:
    return Version(value.split("-", 1)[0])


def assert_frida_compatible(host_version: str, remote_version: str | None) -> None:
    """Require Frida 17+ and exact host/server base version when remote is known."""

    host = _normalise_version(host_version)
    if host.major < 17:
        raise VersionMismatchError(
            f"Host Frida {host_version} is unsupported. Install Frida 17+.",
            advice=("Run: python -m pip install -U frida frida-tools",),
        )
    if remote_version is None:
        return
    remote = _normalise_version(remote_version)
    if remote.major < 17:
        raise VersionMismatchError(
            f"Remote frida-server {remote_version} is unsupported. Install frida-server 17+.",
            advice=("Install a frida-server build matching the host Python frida package.",),
        )
    if host.base_version != remote.base_version:
        raise VersionMismatchError(
            "Frida version mismatch: "
            f"host package is {host_version}, remote server is {remote_version}.",
            advice=(
                "Install the same frida/frida-tools version on the host and "
                "frida-server on the device.",
                "Restart frida-server after replacing the binary.",
            ),
        )


def _remote_version_from_parameters(parameters: dict[str, Any]) -> str | None:
    candidates: list[Any] = [
        parameters.get("frida_server_version"),
        parameters.get("server_version"),
        parameters.get("version"),
    ]
    frida_payload = parameters.get("frida")
    if isinstance(frida_payload, dict):
        candidates.extend(
            [
                frida_payload.get("version"),
                frida_payload.get("server_version"),
            ]
        )
    for candidate in candidates:
        if candidate:
            return str(candidate)
    return None


@dataclass(slots=True)
class FridaSession:
    """Loaded Frida session and script."""

    session: Any
    script: Any
    pid: int
    detached: threading.Event
    detach_reason: str | None = None


class RpcInvoker:
    """Synchronous Frida RPC wrapper with timeout and retry policy."""

    def __init__(self, script: Any) -> None:
        self.script = script

    @property
    def exports(self) -> Any:
        return getattr(self.script, "exports_sync", getattr(self.script, "exports", None))

    def call(self, method: str, *args: Any, timeout: float, retry: int = 0) -> Any:
        if self.exports is None:
            raise RpcCallError("Loaded Frida script does not expose RPC exports.")
        function = getattr(self.exports, method, None)
        if function is None:
            raise RpcCallError(f"Frida agent does not expose rpc.exports.{method}.")
        return call_with_timeout_retry(
            function,
            *args,
            timeout=timeout,
            retry=retry,
            operation=f"rpc.{method}",
        )


def call_with_timeout_retry(
    function: Callable[..., Any],
    *args: Any,
    timeout: float,
    retry: int,
    operation: str,
) -> Any:
    """Run a blocking function with timeout and retry semantics."""

    attempts = max(1, retry + 1)
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(function, *args)
        try:
            return future.result(timeout=timeout)
        except FutureTimeout:
            future.cancel()
            last_error = RpcTimeoutError(
                f"{operation} timed out after {timeout:.1f}s on attempt {attempt}/{attempts}.",
                advice=DEFAULT_RECOVERY_ADVICE,
            )
        except Exception as exc:
            last_error = RpcCallError(
                f"{operation} failed on attempt {attempt}/{attempts}: {exc}",
                advice=DEFAULT_RECOVERY_ADVICE,
            )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        if attempt < attempts:
            time.sleep(min(1.0 * attempt, 3.0))
    if last_error:
        raise last_error
    raise RpcCallError(f"{operation} failed without a captured exception.")


class FridaClient:
    """Connection, app enumeration, attach/spawn, and agent loading helper."""

    def __init__(self, config: ConnectionConfig) -> None:
        self.config = config
        self.frida = _import_frida()
        self.device: Any | None = None

    def connect(self) -> Any:
        host_version = get_host_frida_version()
        try:
            if self.config.host:
                manager = self.frida.get_device_manager()
                self.device = manager.add_remote_device(self.config.host)
            elif self.config.device_id:
                self.device = self.frida.get_device(
                    self.config.device_id, timeout=self.config.timeout
                )
            else:
                self.device = self.frida.get_usb_device(timeout=int(self.config.timeout))
        except Exception as exc:
            raise DeviceConnectionError(
                f"Unable to connect to frida-server: {exc}",
                advice=DEFAULT_RECOVERY_ADVICE,
            ) from exc

        parameters = self._query_system_parameters(required=True)
        remote_version = _remote_version_from_parameters(parameters)
        assert_frida_compatible(host_version, remote_version)
        return self.device

    def _query_system_parameters(self, *, required: bool) -> dict[str, Any]:
        if self.device is None:
            raise DeviceConnectionError("Not connected to a Frida device.")
        try:
            return dict(self.device.query_system_parameters() or {})
        except Exception as exc:
            if required:
                raise DeviceConnectionError(
                    f"Unable to query remote frida-server: {exc}",
                    advice=(
                        "Unlock the device and keep it awake.",
                        "Restart frida-server on the device.",
                        "Use USB instead of WiFi for the first validation.",
                        "Check that host Frida and frida-server versions match.",
                    ),
                ) from exc
            return {}

    def remote_frida_version(self) -> str | None:
        if self.device is None:
            return None
        return _remote_version_from_parameters(self._query_system_parameters(required=False))

    def device_info(self) -> DeviceInfo:
        if self.device is None:
            raise DeviceConnectionError("Not connected to a Frida device.")
        raw = self._query_system_parameters(required=False)
        os_payload = raw.get("os") if isinstance(raw.get("os"), dict) else {}
        return DeviceInfo(
            id=str(getattr(self.device, "id", "")),
            name=str(getattr(self.device, "name", "")),
            type=str(getattr(self.device, "type", "")),
            os=str(os_payload.get("id") or os_payload.get("name") or "") if os_payload else None,
            arch=str(raw.get("arch") or raw.get("platform") or "") if raw else None,
            frida_server_version=_remote_version_from_parameters(raw),
            raw=raw,
        )

    def enumerate_apps(self) -> list[AppInfo]:
        if self.device is None:
            raise DeviceConnectionError("Not connected to a Frida device.")
        try:
            apps = self.device.enumerate_applications(scope="metadata")
        except TypeError:
            apps = self.device.enumerate_applications()
        except Exception as exc:
            raise DeviceConnectionError(f"Failed to enumerate installed apps: {exc}") from exc
        return [app_from_frida(app) for app in apps]

    def attach_or_launch(
        self,
        bundle_id: str,
        *,
        current_pid: int,
        attach_pid: int | None,
        no_launch: bool,
        timeout: float,
        retry: int,
    ) -> FridaSession:
        if self.device is None:
            raise DeviceConnectionError("Not connected to a Frida device.")
        target_pid: int
        spawned = False
        if attach_pid is not None:
            target_pid = attach_pid
        elif current_pid:
            target_pid = current_pid
        elif no_launch:
            raise AppLifecycleError(
                f"{bundle_id} is not running and --no-launch was requested.",
                advice=("Open the app manually, then retry with --no-launch or --attach-pid.",),
            )
        else:
            try:
                target_pid = int(
                    call_with_timeout_retry(
                        self.device.spawn,
                        [bundle_id],
                        timeout=timeout,
                        retry=retry,
                        operation="launching app",
                    )
                )
                spawned = True
            except Exception as exc:
                raise AppLifecycleError(
                    f"Failed to launch {bundle_id}: {exc}",
                    advice=DEFAULT_RECOVERY_ADVICE,
                ) from exc

        def attach() -> Any:
            return self.device.attach(target_pid)

        try:
            session = call_with_timeout_retry(
                attach,
                timeout=timeout,
                retry=retry,
                operation="attaching",
            )
        except Exception as exc:
            raise AppLifecycleError(
                f"Failed to attach to PID {target_pid}: {exc}",
                advice=DEFAULT_RECOVERY_ADVICE,
            ) from exc

        detached = threading.Event()
        state = {"reason": None}

        def on_detached(reason: str, crash: Any = None) -> None:
            state["reason"] = f"{reason}: {crash}" if crash else str(reason)
            detached.set()

        try:
            session.on("detached", on_detached)
        except Exception:
            log.debug("Session detached callback is unavailable.")

        script = self._load_agent(session)
        if spawned:
            try:
                self.device.resume(target_pid)
            except Exception as exc:
                raise AppLifecycleError(
                    f"Attached to {bundle_id}, but resume failed: {exc}",
                    advice=DEFAULT_RECOVERY_ADVICE,
                ) from exc

        return FridaSession(session=session, script=script, pid=target_pid, detached=detached)

    def _load_agent(self, session: Any) -> Any:
        agent_path = Path(__file__).with_name("js") / "agent.js"
        source = agent_path.read_text(encoding="utf-8")
        script = session.create_script(source)

        def on_message(message: dict[str, Any], data: Any) -> None:
            msg_type = message.get("type")
            if msg_type == "error":
                log.error("agent error: %s", message.get("stack") or message.get("description"))
            elif msg_type == "send":
                log.debug("agent: %s", message.get("payload"))
            if data is not None:
                log.debug("agent sent %d byte(s) of binary data", len(data))

        script.on("message", on_message)
        script.load()
        return script

    @staticmethod
    def modules_from_payload(payload: Any) -> list[Any]:
        if not isinstance(payload, list):
            raise RpcCallError("Agent returned invalid module list schema.")
        return [module_info_from_agent(dict(item)) for item in payload]
