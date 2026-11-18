#!/usr/bin/env python3
"""lacp-watchdogd tests, run in a FreeBSD QEMU guest.

The guest has four NICs:
  vtnet0  user-mode networking, SSH only
  vtnet1  192.168.20.2/24, the runner plays the BMC at 192.168.20.1
  vtnet2  192.168.30.2/24, the runner plays the default gateway 192.168.30.254
  vtnet3  192.168.40.2/24, the runner plays a second gateway 192.168.40.254
"""

import lzma
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
import unittest
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from vmtest import (BROADCAST, BUILD_DIR, ETH_P_ARP, ETH_P_IP, SRC_DIR, SSH_KEY, VM, Link,
                    csum, ensure_ssh_key, mac, q, wait_until)

FREEBSD_URL = ("https://download.freebsd.org/ftp/snapshots/VM-IMAGES/16.0-CURRENT/amd64/Latest/"
               "FreeBSD-16.0-CURRENT-amd64-ufs.qcow2.xz")
FREEBSD_DIR = BUILD_DIR / "freebsd"
IMAGE = FREEBSD_DIR / "freebsd-lacp-test.qcow2"
OVMF = [os.environ.get("OVMF", ""), "/usr/share/qemu/OVMF.fd", "/usr/share/ovmf/OVMF.fd",
        "/usr/share/edk2/x64/OVMF.fd"]

BMC_IP, GW_A, GW_B = "192.168.20.1", "192.168.30.254", "192.168.40.254"
HOST_A, HOST_B = "192.168.30.2", "192.168.40.2"
WATCHDOG_PORT = 1190
RESET, SET_TIMEOUT, DISABLE = 0, 1, 2
TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10

PREPARE_CMDS = [
    "sysrc -x ifconfig_DEFAULT",
    "sysrc ifconfig_vtnet0='inet 10.0.2.15/24'",
    "sysrc ifconfig_vtnet1='inet 192.168.20.2/24'",
    "sysrc ifconfig_vtnet2='inet 192.168.30.2/24'",
    "sysrc ifconfig_vtnet3='inet 192.168.40.2/24'",
    f"sysrc defaultrouter={GW_A}",
    "sysrc sshd_enable=YES",
    "echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config",
    "service sshd keygen",
    "mkdir -m 700 -p /root/.ssh",
]


def qemu_args(image: Path) -> list[str]:
    ovmf = next(p for p in OVMF if p and Path(p).exists())
    return ["qemu-system-x86_64", "-machine",
            "accel=kvm" if os.access("/dev/kvm", os.W_OK) else "accel=tcg", "-cpu", "max", "-m", "2048",
            "-smp", "4", "-bios", ovmf, "-display", "none",
            "-drive", f"file={image},if=virtio,format=qcow2"]


def prepare_image() -> None:
    """Derive the test image from the FreeBSD snapshot by configuring it over the serial console."""
    if IMAGE.exists():
        return
    ensure_ssh_key()
    FREEBSD_DIR.mkdir(parents=True, exist_ok=True)
    xz = FREEBSD_DIR / FREEBSD_URL.rsplit("/", 1)[1]
    if not xz.exists():
        print(f"downloading {FREEBSD_URL}", flush=True)
        urllib.request.urlretrieve(FREEBSD_URL, xz.with_suffix(".part"))
        xz.with_suffix(".part").rename(xz)
    tmp = IMAGE.with_suffix(".tmp")
    print(f"decompressing {xz}", flush=True)
    with lzma.open(xz) as src, open(tmp, "wb") as dst:
        shutil.copyfileobj(src, dst, 1 << 24)

    print("configuring FreeBSD over the serial console", flush=True)
    proc = subprocess.Popen(qemu_args(tmp) + ["-serial", "stdio", "-nic", "none"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert proc.stdin and proc.stdout
    out = bytearray()
    cv = threading.Condition()

    def reader() -> None:
        assert proc.stdout
        while data := proc.stdout.read1(4096):
            with cv:
                out.extend(data)
                cv.notify_all()

    def expect(pattern: bytes, timeout: float = 600) -> None:
        with cv:
            if not cv.wait_for(lambda: re.search(pattern, out), timeout):
                raise TimeoutError(f"serial console: no {pattern!r}:\n{out[-2000:].decode(errors='replace')}")
            del out[:]

    def send(line: str) -> None:
        assert proc.stdin
        proc.stdin.write(line.encode() + b"\n")
        proc.stdin.flush()

    threading.Thread(target=reader, daemon=True).start()
    expect(rb"login: ")
    send("root")
    expect(rb"# ")
    pubkey = (SSH_KEY.with_suffix(".pub")).read_text().strip()
    for i, cmd in enumerate(PREPARE_CMDS + [f"echo '{pubkey}' > /root/.ssh/authorized_keys"]):
        send(f"{cmd}; echo done-$?-{i}")
        expect(rf"done-0-{i}\r?\n".encode(), 120)
    send("shutdown -p now")
    proc.wait(300)
    tmp.rename(IMAGE)


@dataclass
class Msg:
    t: float
    conn: int
    op: int
    value: int | None


@dataclass
class Conn:
    id: int
    rcv: int
    snd: int
    buf: bytes = b""
    closed: bool = False


@dataclass
class Ping:
    t: float
    src: str
    dst: str


class Peer:
    """The runner's end of one guest link: answers ARP, ICMP echo and watchdog TCP."""

    conn_ids = iter(range(1, 1 << 30))

    def __init__(self, vm: VM, name: str, our_mac: str, ip: str) -> None:
        self.mac = mac(our_mac)
        self.ip = socket.inet_aton(ip)
        self.echo = True
        self.refuse = False
        self.syns: list[float] = []
        self.lock = threading.Lock()
        self.pings: list[Ping] = []
        self.msgs: list[Msg] = []
        self.conns: dict[tuple[bytes, int], Conn] = {}
        self.conn_list: list[Conn] = []
        self.link = Link(vm.tmp, name, self.rx)

    def rx(self, frame: bytes) -> None:
        dst, src, etype = frame[:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]
        if etype == ETH_P_ARP and frame[20:22] == b"\0\x01" and frame[38:42] == self.ip:
            reply = struct.pack("!HHBBH", 1, ETH_P_IP, 6, 4, 2) + self.mac + self.ip + frame[22:32]
            self.link.send(src + self.mac + struct.pack("!H", ETH_P_ARP) + reply)
        elif etype == ETH_P_IP and frame[30:34] == self.ip:
            ihl = (frame[14] & 0xF) * 4
            proto, sip = frame[23], frame[26:30]
            payload = frame[14 + ihl:14 + struct.unpack("!H", frame[16:18])[0]]
            if proto == 1 and payload[0] == 8:
                with self.lock:
                    self.pings.append(Ping(time.monotonic(), socket.inet_ntoa(sip), socket.inet_ntoa(self.ip)))
                if self.echo:
                    icmp = b"\0\0\0\0" + payload[4:]
                    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
                    self.send_ip(src, sip, 1, icmp)
            elif proto == 6:
                with self.lock:
                    self.tcp(src, sip, payload)

    def send_ip(self, dmac: bytes, dip: bytes, proto: int, payload: bytes) -> None:
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0, self.ip, dip)
        hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
        self.link.send(dmac + self.mac + struct.pack("!H", ETH_P_IP) + hdr + payload)

    def send_tcp(self, dmac: bytes, dip: bytes, dport: int, seq: int, ack: int, flags: int) -> None:
        seg = struct.pack("!HHIIHHHH", WATCHDOG_PORT, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                          (5 << 12) | flags, 65535, 0, 0)
        pseudo = self.ip + dip + struct.pack("!BBH", 0, 6, len(seg))
        seg = seg[:16] + struct.pack("!H", csum(pseudo + seg)) + seg[18:]
        self.send_ip(dmac, dip, 6, seg)

    def tcp(self, smac: bytes, sip: bytes, seg: bytes) -> None:
        sport, dport, seq, _, off_flags = struct.unpack("!HHIIH", seg[:14])
        flags, data = off_flags & 0x3F, seg[(off_flags >> 12) * 4:]
        key = (sip, sport)
        if dport != WATCHDOG_PORT:
            return
        if flags & TCP_RST:
            self.conns.pop(key, None)
            return
        if flags & TCP_SYN:
            self.syns.append(time.monotonic())
            if self.refuse:
                self.send_tcp(smac, sip, sport, 0, seq + 1, TCP_RST | TCP_ACK)
                return
            c = self.conns[key] = Conn(next(self.conn_ids), seq + 1, 1000)
            self.conn_list.append(c)
            self.send_tcp(smac, sip, sport, c.snd, c.rcv, TCP_SYN | TCP_ACK)
            c.snd += 1
            return
        c = self.conns.get(key)
        if c is None:
            return
        if data and seq == c.rcv:
            c.buf += data
            c.rcv += len(data)
            while len(c.buf) >= 5:
                op, n = struct.unpack("!BI", c.buf[:5])
                if len(c.buf) < 5 + n:
                    break
                value = struct.unpack("!I", c.buf[5:9])[0] if n == 4 else None
                self.msgs.append(Msg(time.monotonic(), c.id, op, value))
                c.buf = c.buf[5 + n:]
        if flags & TCP_FIN and seq + len(data) == c.rcv and not c.closed:
            c.rcv += 1
            c.closed = True
            self.send_tcp(smac, sip, sport, c.snd, c.rcv, TCP_FIN | TCP_ACK)
            c.snd += 1
        elif data or flags & TCP_FIN:
            self.send_tcp(smac, sip, sport, c.snd, c.rcv, TCP_ACK)


class WatchdogdTests(unittest.TestCase):
    vm: VM
    bmc: Peer
    upa: Peer
    upb: Peer

    @classmethod
    def setUpClass(cls) -> None:
        prepare_image()
        cls.vm = VM("freebsd", qemu_args(IMAGE) + ["-snapshot"])
        vm = cls.vm
        cls.bmc = Peer(vm, "bmc", "02:00:00:00:20:01", BMC_IP)
        cls.upa = Peer(vm, "upa", "02:00:00:00:30:01", GW_A)
        cls.upb = Peer(vm, "upb", "02:00:00:00:40:01", GW_B)
        args = ["-serial", f"file:{vm.console}",
                "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{vm.ssh_port}-:22",
                "-device", "virtio-net-pci,netdev=n0"]
        for i, peer in enumerate((cls.bmc, cls.upa, cls.upb), 1):
            args += ["-netdev", peer.link.netdev() + f",id=n{i}",
                     "-device", f"virtio-net-pci,netdev=n{i},mac=52:54:00:00:00:0{i}"]
        vm.start(args)
        try:
            vm.wait_ssh(900)
            vm.copy([SRC_DIR / f for f in ("Makefile", "lacp-watchdogd.c", "lacp-watchdog.h",
                                           "net-common.c", "net-common.h", "init/lacp_watchdogd.rc.in")],
                    "/root/src")
            vm.run("cd /root/src && make lacp-watchdogd && "
                   "install -m 755 lacp-watchdogd /usr/local/sbin/ && "
                   "sed 's|%%PREFIX%%|/usr/local|' init/lacp_watchdogd.rc.in > /usr/local/etc/rc.d/lacp_watchdogd && "
                   "chmod 755 /usr/local/etc/rc.d/lacp_watchdogd && sysrc lacp_watchdogd_enable=YES")
        except Exception:
            vm.stop()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.vm.stop()

    def setUp(self) -> None:
        self.vm.run("service lacp_watchdogd stop >/dev/null 2>&1; "
                    "ifconfig vtnet2 up; ifconfig vtnet3 up; "
                    f"route -q delete default {GW_B}; route -nq get default >/dev/null || route -q add default {GW_A}",
                    check=False)
        for peer in (self.bmc, self.upa, self.upb):
            peer.echo = True
            peer.refuse = False

    def start(self, args: str) -> None:
        self.log_start = int(self.vm.run("wc -l < /var/log/messages"))
        self.t0 = time.monotonic()
        self.vm.run(f"sysrc lacp_watchdogd_args={q(args)} && service lacp_watchdogd start </dev/null >/dev/null 2>&1")

    def log(self) -> list[str]:
        return [line for line in self.vm.run(f"tail -n +{self.log_start + 1} /var/log/messages").splitlines()
                if "lacp-watchdogd" in line]

    def wait_log(self, text: str, timeout: float = 10) -> None:
        if not wait_until(lambda: any(text in line for line in self.log()), timeout, 1):
            self.fail(f"{text!r} not logged:\n" + "\n".join(self.log()))

    def msgs(self, since: float = 0, op: int | None = None) -> list[Msg]:
        with self.bmc.lock:
            return [m for m in self.bmc.msgs if m.t >= max(since, self.t0) and (op is None or m.op == op)]

    def wait_resets(self, n: int = 1, since: float = 0, timeout: float = 15) -> list[Msg]:
        if not wait_until(lambda: len(self.msgs(since, RESET)) >= n, timeout):
            self.fail(f"expected {n} RESETs, got {len(self.msgs(since, RESET))}")
        return self.msgs(since, RESET)

    def pings(self, peer: Peer, since: float = 0) -> list[Ping]:
        with peer.lock:
            return [p for p in peer.pings if p.t >= max(since, self.t0)]

    def assert_resets_stop(self) -> None:
        time.sleep(2)
        t = time.monotonic()
        time.sleep(4)
        self.assertEqual(self.msgs(t, RESET), [])

    def assert_no_errors(self) -> None:
        errors = [line for line in self.log() if re.search(r"lacp-watchdogd\[\d+\]: lacp-watchdogd:", line)]
        self.assertEqual(errors, [])

    def test_service_started(self) -> None:
        self.start("-d")
        self.assertIn("is running", self.vm.run("service lacp_watchdogd status"))
        resets = self.wait_resets(3)
        self.assertEqual(len({m.conn for m in resets}), 1)
        self.assertEqual(self.msgs(op=SET_TIMEOUT), [])
        self.assertTrue(all(p.src == HOST_A for p in self.pings(self.upa)))
        self.assertGreaterEqual(len(self.pings(self.upa)), 3)
        self.wait_log("sent watchdog reset")
        self.assert_no_errors()

    def test_service_restart(self) -> None:
        self.start("-d")
        old = self.wait_resets()[0].conn
        pid = self.vm.run("pgrep -x lacp-watchdogd").strip()
        t = time.monotonic()
        self.vm.run("service lacp_watchdogd restart </dev/null >/dev/null 2>&1")
        resets = self.wait_resets(3, since=t)
        self.assertNotEqual(resets[-1].conn, old)
        self.assertTrue(next(c for c in self.bmc.conn_list if c.id == old).closed)
        self.assertNotEqual(self.vm.run("pgrep -x lacp-watchdogd").strip(), pid)
        self.assert_no_errors()

    def test_set_timeout_option(self) -> None:
        self.start("-d -t 7")
        self.wait_resets()
        first = self.msgs()[0]
        self.assertEqual((first.op, first.value), (SET_TIMEOUT, 7))
        self.assertEqual(len(self.msgs(op=SET_TIMEOUT)), 1)

    def test_reset_period_option(self) -> None:
        for period in (1, 3):
            with self.subTest(period=period):
                self.setUp()
                self.start(f"-d -r {period}")
                resets = self.wait_resets(4, timeout=5 * period + 10)
                for a, b in zip(resets, resets[1:]):
                    self.assertAlmostEqual(b.t - a.t, period, delta=0.6)

    def test_interface_option(self) -> None:
        self.vm.run(f"route change default {GW_B}")
        self.start("-d -i vtnet3")
        self.wait_resets(3)
        self.assertEqual(self.pings(self.upa), [])
        self.assertTrue(self.pings(self.upb))
        self.assertTrue(all(p.src == HOST_B for p in self.pings(self.upb)))

        self.setUp()
        self.vm.run(f"route change default {GW_B}")
        self.start("-d -i vtnet2")
        self.wait_log("no default gateway found")
        time.sleep(3)
        self.assertEqual(self.msgs(op=RESET), [])
        self.assertEqual(self.pings(self.upa) + self.pings(self.upb), [])

    def test_multipath_gateways(self) -> None:
        for iface, peer, other, src in (("", None, None, None), ("vtnet2", self.upa, self.upb, HOST_A),
                                        ("vtnet3", self.upb, self.upa, HOST_B)):
            with self.subTest(iface=iface):
                self.setUp()
                self.vm.run(f"route add default {GW_B}")
                self.start(f"-d -i {iface}" if iface else "-d")
                self.wait_resets(3)
                if peer and other:
                    self.assertEqual(self.pings(other), [])
                    self.assertTrue(self.pings(peer))
                    self.assertTrue(all(p.src == src for p in self.pings(peer)))

    def test_bmc_unreachable(self) -> None:
        self.bmc.refuse = True
        self.start("-d")
        time.sleep(8)
        with self.bmc.lock:
            attempts = [t for t in self.bmc.syns if t >= self.t0]
        self.assertGreaterEqual(len(attempts), 3)
        self.assertIn("is running", self.vm.run("service lacp_watchdogd status"))
        self.bmc.refuse = False
        self.wait_resets(timeout=15)

    def test_gateway_removed(self) -> None:
        self.start("-d")
        self.wait_resets()
        self.vm.run("route delete default")
        self.assert_resets_stop()
        self.wait_log("no default gateway found")
        t = time.monotonic()
        self.vm.run(f"route add default {GW_A}")
        self.wait_resets(since=t)

    def test_no_icmp_response(self) -> None:
        self.start("-d")
        self.wait_resets()
        self.upa.echo = False
        t = time.monotonic()
        self.assert_resets_stop()
        self.assertGreaterEqual(len(self.pings(self.upa, t)), 3)
        self.wait_log("gateway unreachable")
        t = time.monotonic()
        self.upa.echo = True
        self.wait_resets(since=t)

    def test_interface_down(self) -> None:
        self.start("-d")
        self.wait_resets()
        self.vm.run("ifconfig vtnet2 down")
        self.assert_resets_stop()
        t = time.monotonic()
        self.vm.run(f"ifconfig vtnet2 up; route -nq get default >/dev/null || route add default {GW_A}")
        self.wait_resets(since=t)


if __name__ == "__main__":
    unittest.main(verbosity=2)
