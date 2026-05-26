"""Paramiko/SFTP filesystem operations."""

from __future__ import annotations

import posixpath
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import paramiko
from paramiko.ssh_exception import AuthenticationException

from .config import SshConfig
from .errors import SshError

ProgressCallback = Callable[[str, int, int], None]


@dataclass(frozen=True, slots=True)
class RemoteCommandResult:
    """Result of a constant remote shell command."""

    exit_status: int
    stdout: str
    stderr: str


class SshClient:
    """Small SFTP-first wrapper around Paramiko."""

    def __init__(self, config: SshConfig) -> None:
        if not config.enabled:
            raise SshError("SSH config is incomplete. Provide --ssh-host and --ssh-user.")
        self.config = config
        self.client: paramiko.SSHClient | None = None
        self.sftp: paramiko.SFTPClient | None = None

    def connect(self) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.config.host,
                port=self.config.port,
                username=self.config.user,
                password=self.config.password,
                key_filename=str(self.config.key_filename) if self.config.key_filename else None,
                timeout=self.config.timeout,
                auth_timeout=self.config.timeout,
                banner_timeout=self.config.timeout,
                look_for_keys=self.config.key_filename is None and self.config.password is None,
            )
            self.sftp = client.open_sftp()
            self.client = client
        except AuthenticationException as exc:
            advice = [
                "Provide --ssh-pass or --ssh-key, or omit SSH options to use Frida transfer.",
                "For iproxy, use --ssh-host 127.0.0.1 --ssh-port 2222.",
            ]
            if self.config.password is None and self.config.key_filename is None:
                advice.insert(
                    0,
                    "No SSH password or key was supplied; key-agent authentication failed.",
                )
            raise SshError(
                "SSH authentication failed for "
                f"{self.config.user}@{self.config.host}:{self.config.port}: {exc}",
                advice=tuple(advice),
            ) from exc
        except Exception as exc:
            raise SshError(
                "SSH connection failed for "
                f"{self.config.user}@{self.config.host}:{self.config.port}: {exc}",
                advice=(
                    "Check --ssh-host, --ssh-port, --ssh-user, and key/password settings.",
                    "For iproxy, use --ssh-host 127.0.0.1 --ssh-port 2222.",
                ),
            ) from exc

    def close(self) -> None:
        if self.sftp is not None:
            self.sftp.close()
            self.sftp = None
        if self.client is not None:
            self.client.close()
            self.client = None

    def __enter__(self) -> SshClient:
        self.connect()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def run_constant(self, command: str, timeout: float = 15.0) -> RemoteCommandResult:
        """Run a fixed diagnostic command. Do not pass user-controlled app names."""

        if self.client is None:
            raise SshError("SSH client is not connected.")
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            stdin.close()
            exit_status = stdout.channel.recv_exit_status()
            return RemoteCommandResult(
                exit_status=exit_status,
                stdout=stdout.read().decode("utf-8", errors="replace"),
                stderr=stderr.read().decode("utf-8", errors="replace"),
            )
        except Exception as exc:
            raise SshError(f"Remote command failed: {command}: {exc}") from exc

    def exists(self, remote_path: str) -> bool:
        if self.sftp is None:
            raise SshError("SFTP client is not connected.")
        try:
            self.sftp.stat(remote_path)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return False

    def mkdir_p(self, remote_path: str) -> None:
        if self.sftp is None:
            raise SshError("SFTP client is not connected.")
        current = ""
        for part in remote_path.split("/"):
            if not part:
                current = "/"
                continue
            current = posixpath.join(current, part) if current != "/" else f"/{part}"
            with suppress(OSError):
                self.sftp.mkdir(current)

    def download_file(
        self, remote_path: str, local_path: Path, progress: ProgressCallback | None = None
    ) -> None:
        if self.sftp is None:
            raise SshError("SFTP client is not connected.")
        local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            size = int(self.sftp.stat(remote_path).st_size)
            transferred = 0

            def callback(done: int, total: int) -> None:
                nonlocal transferred
                transferred = done
                if progress:
                    progress(remote_path, total or size, done)

            self.sftp.get(remote_path, str(local_path), callback=callback)
            if progress and transferred < size:
                progress(remote_path, size, size)
        except Exception as exc:
            raise SshError(f"Failed to download {remote_path}: {exc}") from exc

    def download_tree(
        self,
        remote_path: str,
        local_path: Path,
        progress: ProgressCallback | None = None,
    ) -> None:
        if self.sftp is None:
            raise SshError("SFTP client is not connected.")
        local_path.mkdir(parents=True, exist_ok=True)
        try:
            self._download_tree(remote_path.rstrip("/"), local_path, progress)
        except Exception as exc:
            raise SshError(f"Failed to download tree {remote_path}: {exc}") from exc

    def _download_tree(
        self,
        remote_path: str,
        local_path: Path,
        progress: ProgressCallback | None,
    ) -> None:
        assert self.sftp is not None
        for item in self.sftp.listdir_attr(remote_path):
            remote_child = posixpath.join(remote_path, item.filename)
            local_child = local_path / item.filename
            mode = item.st_mode
            if stat.S_ISDIR(mode):
                local_child.mkdir(exist_ok=True)
                self._download_tree(remote_child, local_child, progress)
            elif stat.S_ISLNK(mode):
                target = self.sftp.readlink(remote_child)
                local_child.parent.mkdir(parents=True, exist_ok=True)
                if local_child.exists() or local_child.is_symlink():
                    local_child.unlink()
                local_child.symlink_to(target)
            elif stat.S_ISREG(mode):
                self.download_file(remote_child, local_child, progress)
                local_child.chmod(mode & 0o777)

    def remove_tree(self, remote_path: str) -> None:
        if self.sftp is None:
            raise SshError("SFTP client is not connected.")
        if not self.exists(remote_path):
            return
        self._remove_tree(remote_path.rstrip("/"))

    def _remove_tree(self, remote_path: str) -> None:
        assert self.sftp is not None
        try:
            attrs = self.sftp.listdir_attr(remote_path)
        except OSError:
            self.sftp.remove(remote_path)
            return
        for item in attrs:
            child = posixpath.join(remote_path, item.filename)
            if stat.S_ISDIR(item.st_mode):
                self._remove_tree(child)
            else:
                self.sftp.remove(child)
        self.sftp.rmdir(remote_path)
