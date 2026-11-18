"""Shared helpers for the QEMU based lacp-takeoverd and lacp-watchdogd tests."""

import os
import re
import shlex
import socket
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
SRC_DIR = TESTS_DIR.parent
BUILD_DIR = Path(os.environ.get("BUILD_DIR", TESTS_DIR / "build")).resolve()
SSH_KEY = BUILD_DIR / "id_ed25519"

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_SLOW = 0x8809
BROADCAST = b"\xff" * 6


def ensure_ssh_key() -> None:
    if not SSH_KEY.exists():
        BUILD_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(SSH_KEY)], check=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def mac(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def wait_until(cond: Callable[[], object], timeout: float, interval: float = 0.2) -> object:
    deadline = time.monotonic() + timeout
    while True:
        r = cond()
        if r or time.monotonic() > deadline:
            return r
        time.sleep(interval)


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class Link:
    """An L2 link to a QEMU NIC, carried over a unix datagram socket pair."""

    def __init__(self, tmp: Path, name: str, handler: Callable[[bytes], None]) -> None:
        self.ours = str(tmp / f"{name}-runner.sock")
        self.theirs = str(tmp / f"{name}-qemu.sock")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(self.ours)
        self.handler = handler
        threading.Thread(target=self._rx, daemon=True).start()

    def netdev(self) -> str:
        return (f"dgram,local.type=unix,local.path={self.theirs},"
                f"remote.type=unix,remote.path={self.ours}")

    def send(self, frame: bytes) -> None:
        try:
            self.sock.sendto(frame, self.theirs)
        except OSError:
            pass

    def _rx(self) -> None:
        while True:
            try:
                frame = self.sock.recv(65536)
            except OSError:
                return
            self.handler(frame)


class VM:
    """A QEMU guest managed over its serial console and SSH."""

    def __init__(self, name: str, qemu_args: list[str]) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix=f"{name}-"))
        self.ssh_port = free_port()
        self.console = self.tmp / "console.log"
        self.qemu_args = qemu_args
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self, extra: list[str]) -> None:
        with open(self.tmp / "qemu.log", "wb") as log:
            self.proc = subprocess.Popen(self.qemu_args + extra, stdin=subprocess.DEVNULL,
                                         stdout=log, stderr=subprocess.STDOUT)

    def stop(self) -> None:
        if self.proc:
            self.proc.kill()
            self.proc.wait()

    def ssh_cmd(self, cmd: str) -> list[str]:
        return ["ssh", "-F", "/dev/null", "-i", str(SSH_KEY), "-p", str(self.ssh_port),
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
                "-o", "ControlMaster=auto", "-o", f"ControlPath={self.tmp}/ssh.sock",
                "-o", "ControlPersist=600", "root@127.0.0.1", cmd]

    def run(self, cmd: str, check: bool = True, timeout: float = 120) -> str:
        r = subprocess.run(self.ssh_cmd(cmd), capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"`{cmd}` failed ({r.returncode}): {r.stdout}{r.stderr}")
        return r.stdout

    def copy(self, files: list[Path], dest: str) -> None:
        tar = subprocess.Popen(["tar", "-C", str(SRC_DIR), "-cf", "-"] +
                               [str(f.relative_to(SRC_DIR)) for f in files], stdout=subprocess.PIPE)
        subprocess.run(self.ssh_cmd(f"mkdir -p {dest} && tar -C {dest} -xf -"), stdin=tar.stdout, check=True)
        tar.wait()

    def wait_ssh(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(f"QEMU exited, see {self.console}")
            try:
                if subprocess.run(self.ssh_cmd("true"), capture_output=True, timeout=30).returncode == 0:
                    return
            except subprocess.TimeoutExpired:
                pass
            time.sleep(5)
        raise TimeoutError(f"no SSH after {timeout}s, see {self.console}")


class LogStream:
    """Collects lines from a long-running remote command, e.g. `journalctl -f`."""

    def __init__(self, vm: VM, cmd: str, log: Path) -> None:
        self.lines: list[str] = []
        self.log = open(log, "w")
        self.cv = threading.Condition()
        self.proc = subprocess.Popen(vm.ssh_cmd(cmd), stdout=subprocess.PIPE, text=True)
        threading.Thread(target=self._rx, daemon=True).start()

    def _rx(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            self.log.write(line)
            self.log.flush()
            with self.cv:
                self.lines.append(line.rstrip("\n"))
                self.cv.notify_all()

    def mark(self) -> int:
        with self.cv:
            return len(self.lines)

    def since(self, mark: int) -> list[str]:
        with self.cv:
            return self.lines[mark:]

    def wait(self, pattern: str, timeout: float, since: int = 0) -> tuple[int, re.Match[str]]:
        """Return (index, match) of the first line at or after `since` matching pattern."""
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        i = since
        with self.cv:
            while True:
                for i in range(i, len(self.lines)):
                    if m := rx.search(self.lines[i]):
                        return i, m
                i = len(self.lines)
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError(f"no log line matching {pattern!r} within {timeout}s")
                self.cv.wait(left)

    def count(self, pattern: str, since: int = 0) -> int:
        return sum(1 for line in self.since(since) if re.search(pattern, line))

    def close(self) -> None:
        self.proc.kill()


def q(s: str) -> str:
    return shlex.quote(s)
