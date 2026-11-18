#!/usr/bin/env python3
"""lacp-takeoverd tests, run in an OpenBMC (AST2600 EVB) QEMU guest. Build it with build-openbmc.sh.

The guest has two NICs:
  eth0  user-mode networking at 192.168.20.1, SSH and the watchdog port are forwarded to it
  eth1  the NCSI interface (10.10.10.2/24 via 10.10.10.1), the runner plays the LACP switch
"""

import re
import resource
import socket
import struct
import threading
import time
import unittest

from vmtest import BUILD_DIR, ETH_P_SLOW, VM, Link, LogStream, free_port, mac, mac_str, q, wait_until

IMAGE = BUILD_DIR / "openbmc/tmp/deploy/images/canopy-qemu/obmc-phosphor-image-canopy-qemu.static.mtd"

LACP_DST = mac("01:80:c2:00:00:02")
SWITCH_MAC = mac("02:00:00:00:00:01")
HOST_MAC = mac("02:00:00:00:00:02")
ACTIVITY, TIMEOUT, AGGREGATION, SYNC, COLLECTING, DISTRIBUTING, DEFAULTED = 1, 2, 4, 8, 16, 32, 64
UP = ACTIVITY | TIMEOUT | AGGREGATION | SYNC | COLLECTING | DISTRIBUTING
RESET, SET_TIMEOUT, DISABLE = 0, 1, 2

READY = r"listening for watchdog messages"
TAKEN = r"took over LACP on eth1"
BACK = r"LACP bundle restored to the host"
WARNING = r"lacp-takeoverd\[\d+\]: lacp-takeoverd: "

CLEANUP = """
rm -rf /run/systemd/network/*.d
if [ -e /sys/class/net/bond0 ]; then echo -bond0 > /sys/class/net/bonding_masters; fi
networkctl reload
networkctl reconfigure eth1
for i in $(seq 150); do
    [ -e /sys/class/net/bond0 ] && ip -4 addr show eth1 | grep -q 10.10.10.2/24 &&
        ip route | grep -q 'default via 10.10.10.1 dev eth1' && break
    sleep 0.2
done
"""


def lacpdu(state: int, partner: bytes = bytes(6), partner_state: int = 0) -> bytes:
    actor = struct.pack("!BBH6sHHHB3x", 1, 20, 0x8000, SWITCH_MAC, 1, 0x8000, 1, state)
    peer = struct.pack("!BBH6sHHHB3x", 2, 20, 0x8000, partner, 1, 0x8000, 1, partner_state)
    collector = struct.pack("!BBH12x", 3, 16, 0)
    return LACP_DST + SWITCH_MAC + struct.pack("!HBB", ETH_P_SLOW, 1, 1) + actor + peer + collector + bytes(52)


DEFAULTED_PDU = lacpdu(ACTIVITY | TIMEOUT | AGGREGATION | DEFAULTED)


def partner_pdu(partner: bytes) -> bytes:
    return lacpdu(UP, partner, UP)


def set_mac(addr: str) -> str:
    return f"ip link set eth1 down; ip link set eth1 address {addr}; ip link set eth1 up"


def ts(line: str) -> float:
    return float(line[1:line.index("]")])


class Switch:
    """The runner's end of the NCSI link: an LACP partner that sends `pdu` every second."""

    def __init__(self, vm: VM) -> None:
        self.pdu: bytes | None = None
        self.lock = threading.Lock()
        self.rx_pdus: list[tuple[float, bytes]] = []
        self.link = Link(vm.tmp, "ncsi", self.rx)
        threading.Thread(target=self.tx, daemon=True).start()

    def rx(self, frame: bytes) -> None:
        if frame[12:15] == struct.pack("!HB", ETH_P_SLOW, 1):
            with self.lock:
                self.rx_pdus.append((time.monotonic(), frame))

    def tx(self) -> None:
        while True:
            if pdu := self.pdu:
                self.link.send(pdu)
            time.sleep(1)

    def received(self, since: float) -> list[bytes]:
        with self.lock:
            return [f for t, f in self.rx_pdus if t >= since]


class Watchdog:
    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port))

    def send(self, op: int, payload: bytes = b"") -> None:
        self.sock.sendall(struct.pack("!BI", op, len(payload)) + payload)

    def close(self) -> None:
        self.sock.close()


class TakeoverdTests(unittest.TestCase):
    maxDiff = None
    vm: VM
    switch: Switch
    journal: LogStream
    wd_port: int

    @classmethod
    def setUpClass(cls) -> None:
        if not IMAGE.exists():
            raise unittest.SkipTest(f"{IMAGE} missing, run build-openbmc.sh")
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        cls.vm = vm = VM("openbmc", ["qemu-system-arm", "-M", "ast2600-evb", "-display", "none",
                                     "-drive", f"file={IMAGE},format=raw,if=mtd", "-snapshot"])
        cls.switch = Switch(vm)
        cls.wd_port = free_port()
        vm.start(["-serial", f"file:{vm.console}",
                  "-netdev", f"user,id=mgmt,net=192.168.20.0/24,host=192.168.20.2,"
                             f"hostfwd=tcp:127.0.0.1:{vm.ssh_port}-192.168.20.1:22,"
                             f"hostfwd=tcp:127.0.0.1:{cls.wd_port}-192.168.20.1:1190",
                  "-net", "nic,netdev=mgmt",
                  "-netdev", cls.switch.link.netdev() + ",id=ncsi",
                  "-net", "nic,netdev=ncsi,macaddr=52:54:00:00:00:01"])
        try:
            vm.wait_ssh(1200)
            cls.journal = LogStream(vm, "journalctl -f -n all -o short-monotonic", vm.tmp / "journal.log")
        except Exception:
            vm.stop()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.journal.close()
        cls.vm.stop()

    def setUp(self) -> None:
        self.wds: list[Watchdog] = []
        self.switch.pdu = None

    def tearDown(self) -> None:
        for wd in self.wds:
            wd.close()

    def start(self, args: str, prep: str = "") -> None:
        self.switch.pdu = None
        self.vm.run(f"systemctl stop lacp-takeoverd\n{CLEANUP}\n{prep}\n"
                    f"echo LACP_TAKEOVER_ARGS={q(args)} > /etc/lacp-takeover.conf")
        self.mark = self.journal.mark()
        self.vm.run("systemctl reset-failed lacp-takeoverd; systemctl start lacp-takeoverd")
        self.wait(READY, 30)
        self.t0 = time.monotonic()

    def wait(self, pattern: str, timeout: float = 15, since: int | None = None) -> tuple[int, float]:
        i, _ = self.journal.wait(pattern, timeout, self.mark if since is None else since)
        return i, ts(self.journal.lines[i])

    def count(self, pattern: str, since: int | None = None) -> int:
        return self.journal.count(pattern, self.mark if since is None else since)

    def watchdog(self) -> Watchdog:
        wd = Watchdog(self.wd_port)
        self.wds.append(wd)
        return wd

    def wd_send(self, op: int, payload: bytes = b"", expect: str = "") -> tuple[int, float]:
        if not self.wds:
            self.watchdog()
        mark = self.journal.mark()
        self.wds[0].send(op, payload)
        return self.wait(expect or r"watchdog (reset|timeout set|disabled)", 10, mark)

    def reset(self, timeout: int = 4) -> tuple[int, float]:
        return self.wd_send(RESET, expect=rf"watchdog reset \(timeout {timeout}s\)")

    def eth1_mac(self) -> str:
        return self.vm.run("cat /sys/class/net/eth1/address").strip()

    def assert_taken_over(self) -> None:
        out = self.vm.run("readlink /sys/class/net/eth1/master; cat /sys/class/net/bond0/address; "
                          "ip -4 addr show eth1; echo ---; ip -4 addr show bond0; echo ---; ip route")
        master, bond_mac, rest = out.split("\n", 2)
        eth1, bond0, routes = rest.split("---")
        self.assertTrue(master.endswith("/bond0"), out)
        self.assertEqual(bond_mac, self.eth1_mac())
        self.assertNotIn("10.10.10.2", eth1)
        self.assertIn("10.10.10.2/24", bond0)
        self.assertRegex(routes, r"default via 10.10.10.1 dev bond0")

    def assert_handed_back(self) -> None:
        out = self.vm.run("ls /sys/class/net/eth1/master 2>&1; "
                          "ip -4 addr show eth1; echo ---; ip -4 addr show bond0; echo ---; ip route")
        master, rest = out.split("\n", 1)
        eth1, bond0, routes = rest.split("---")
        self.assertIn("No such file", master)
        self.assertIn("10.10.10.2/24", eth1)
        self.assertNotIn("10.10.10.2", bond0)
        self.assertRegex(routes, r"default via 10.10.10.1 dev eth1")
        self.assertNotRegex(routes, r"dev bond0")

    def assert_running_clean(self) -> None:
        self.assertEqual(self.vm.run("systemctl is-active lacp-takeoverd", check=False).strip(), "active")
        self.assertEqual([line for line in self.journal.since(self.mark) if re.search(WARNING, line)], [])

    def take_over(self, pdu: bytes = DEFAULTED_PDU) -> float:
        mark = self.journal.mark()
        self.switch.pdu = pdu
        _, t = self.wait(TAKEN, since=mark)
        return t

    def bmc_pdus(self, since: float, n: int = 1, timeout: float = 10) -> list[bytes]:
        if not wait_until(lambda: len(self.switch.received(since)) >= n, timeout):
            self.fail(f"expected {n} LACPDUs from the BMC, got {len(self.switch.received(since))}")
        return self.switch.received(since)

    def net_state(self) -> str:
        # bond0 gets a new random MAC when its last slave is released.
        return re.sub(r"(: bond0: .*\n\s+link/ether )\S+", r"\1<random>",
                      self.vm.run("ip addr; ip route; ip -6 route"))

    def addrs_routes(self, dev: str) -> tuple[set[str], set[str]]:
        addrs, routes = self.vm.run(f"ip addr show {dev}; echo ---; ip route; ip -6 route").split("---")
        return (set(re.findall(r"inet6? (\S+)", addrs)),
                {re.sub(r" dev \S+", "", r).strip() for r in routes.splitlines()
                 if r.startswith("default") and f" dev {dev} " in r + " "})

    def check_transfer(self, conf: str) -> None:
        d = "/etc/systemd/network/10-eth1.network.d"
        self.addCleanup(self.vm.run, f"rm -rf {d}; networkctl reload; networkctl reconfigure eth1")
        self.start("-d -t 0", prep=f"mkdir -p {d} && printf '%s\\n' {q(conf)} > {d}/test.conf && "
                                   "networkctl reload && networkctl reconfigure eth1")
        before = self.stable_net_state()
        moved = self.addrs_routes("eth1")
        self.take_over()
        self.stable_net_state()
        self.assertEqual(self.addrs_routes("bond0"), moved)
        self.assertEqual(self.addrs_routes("eth1"), (set(), set()))
        self.switch.pdu = partner_pdu(HOST_MAC)
        self.wait(BACK)
        self.assertEqual(self.stable_net_state(), before)
        self.assert_running_clean()

    def stable_net_state(self, timeout: float = 15) -> str:
        prev = self.net_state()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(1)
            cur = self.net_state()
            if cur == prev:
                return cur
            prev = cur
        self.fail("network state did not settle")

    def bond_conf(self, conf: str = "") -> None:
        conf = (f"mkdir -p /etc/systemd/network/00-bmc-bond0.netdev.d && "
                f"printf '[Bond]\\n{conf}\\n' > /etc/systemd/network/00-bmc-bond0.netdev.d/test.conf" if conf else "")
        self.vm.run(f"systemctl stop lacp-takeoverd\n{CLEANUP}\nrm -rf /etc/systemd/network/00-bmc-bond0.netdev.d\n{conf}")

    # General

    def test_00_running_clean(self) -> None:
        self.assertEqual(self.vm.run("systemctl is-active lacp-takeoverd", check=False).strip(), "active")
        self.assertEqual(self.vm.run("systemctl show -P NRestarts lacp-takeoverd").strip(), "0")
        log = self.vm.run("journalctl -b -u lacp-takeoverd -o cat")
        self.assertIn("listening for watchdog messages", log)
        self.assertNotRegex(log, r"(?m)^lacp-takeoverd: ")

    def test_01_restart(self) -> None:
        self.start("-d")
        pid = self.vm.run("systemctl show -P MainPID lacp-takeoverd").strip()
        self.mark = self.journal.mark()
        self.vm.run("systemctl restart lacp-takeoverd")
        self.wait(READY, 30)
        self.assertNotEqual(self.vm.run("systemctl show -P MainPID lacp-takeoverd").strip(), pid)
        self.assert_running_clean()

    def test_takeover(self) -> None:
        self.start("-d")
        self.switch.pdu = DEFAULTED_PDU
        i, _ = self.wait(r"watchdog expired")
        self.wait(TAKEN, since=i)
        self.assert_taken_over()
        pdu = self.bmc_pdus(self.t0)[-1]
        self.assertEqual(mac_str(pdu[20:26]), self.eth1_mac())
        self.assert_running_clean()

    def test_handback(self) -> None:
        self.start("-d")
        self.take_over()
        self.switch.pdu = partner_pdu(HOST_MAC)
        self.reset()
        self.wait(BACK)
        self.assert_handed_back()
        self.assert_running_clean()

    def test_handback_restores_network(self) -> None:
        self.start("-d -t 0")
        before = self.stable_net_state()
        self.take_over()
        self.assert_taken_over()
        self.switch.pdu = partner_pdu(HOST_MAC)
        self.wait(BACK)
        self.assertEqual(self.stable_net_state(), before)
        self.assert_running_clean()

    def test_kill_while_owning(self) -> None:
        self.start("-d -t 0")
        self.take_over()
        self.vm.run("systemctl kill -s KILL lacp-takeoverd")
        self.switch.pdu = partner_pdu(HOST_MAC)
        self.assert_taken_over()
        self.mark = self.journal.mark()
        self.vm.run("systemctl restart lacp-takeoverd")
        self.wait(r"lacp-takeoverd: started with eth1 enslaved to bond0", 30)
        self.wait(READY, 30)
        self.assert_handed_back()
        self.assertEqual(self.vm.run("find /run/systemd/network -name 99-lacp-takeover.conf"), "")
        self.take_over()
        self.assert_taken_over()

    def test_networkd_reload_restart(self) -> None:
        for cmd in ("networkctl reload", "systemctl restart systemd-networkd"):
            with self.subTest(cmd):
                self.start("-d -t 0")
                self.take_over()
                self.vm.run(cmd)
                self.stable_net_state()
                self.assert_taken_over()
                self.switch.pdu = partner_pdu(HOST_MAC)
                self.wait(BACK)
                self.assert_handed_back()
                self.assert_running_clean()

    def test_ipv6_transfer(self) -> None:
        self.check_transfer("[Network]\nAddress=fd00::2/64\nGateway=fd00::1")

    def test_many_addresses_transfer(self) -> None:
        conf = "[Network]\n" + "".join(f"Address=10.10.10.{i}/24\n" for i in range(10, 20))
        conf += "".join(f"\n[Route]\nGateway=10.10.10.{i}\nMetric={i * 10}\n" for i in range(3, 8))
        self.check_transfer(conf)

    # LACP

    def test_lacp_enslaved_at_start(self) -> None:
        self.start("-d -t 0", prep="ip link set eth1 down; echo +eth1 > /sys/class/net/bond0/bonding/slaves; "
                                   "readlink /sys/class/net/eth1/master")
        self.wait(r"lacp-takeoverd: started with eth1 enslaved to bond0")
        self.wait(r"lacp-takeoverd: restoring eth1 to its systemd-networkd configuration")
        self.assertEqual(self.vm.run("systemctl is-active lacp-takeoverd").strip(), "active")
        self.assert_handed_back()

    def test_lacp_transmit_rate(self) -> None:
        self.addCleanup(self.bond_conf)
        for rate, bit in (("slow", 0), ("fast", TIMEOUT)):
            with self.subTest(rate=rate):
                self.bond_conf(f"LACPTransmitRate={rate}")
                self.start("-d -t 0")
                t = self.take_over()
                self.assert_taken_over()
                self.assertTrue(self.vm.run("cat /sys/class/net/bond0/bonding/lacp_rate").startswith(rate))
                for pdu in self.bmc_pdus(self.t0, 2):
                    self.assertEqual(pdu[32] & TIMEOUT, bit)
                self.assert_running_clean()

    def test_lacp_active_passive(self) -> None:
        self.addCleanup(self.bond_conf)
        passive_switch = lacpdu(TIMEOUT | AGGREGATION | DEFAULTED)
        self.bond_conf("LACPTransmitRate=fast")
        for mode in ("on", "off"):
            with self.subTest(lacp_active=mode):
                # systemd-networkd does not support LACPActive=.
                self.start("-d -t 0", prep="ip link set bond0 down; "
                                           f"echo {mode} > /sys/class/net/bond0/bonding/lacp_active; "
                                           "ip link set bond0 up")
                self.take_over(passive_switch)
                self.assert_taken_over()
                self.switch.pdu = None
                time.sleep(10)
                t = time.monotonic()
                # Once the partner defaults, an active bond falls back to the slow periodic rate (30s).
                time.sleep(45)
                pdus = self.switch.received(t)
                if mode == "on":
                    self.assertGreaterEqual(len(pdus), 1)
                    self.assertTrue(all(p[32] & ACTIVITY for p in pdus))
                else:
                    self.assertEqual(pdus, [])
                self.assert_running_clean()

    def test_lacp_corrupted_pdus(self) -> None:
        def pad(f: bytes) -> bytes:
            return f + bytes(max(0, 60 - len(f)))

        def corrupt(f: bytes, off: int, val: int) -> bytes:
            return f[:off] + bytes([val]) + f[off + 1:]

        host = partner_pdu(HOST_MAC)
        cases = {
            "short": DEFAULTED_PDU[:40],
            "truncated actor": pad(DEFAULTED_PDU[:36]),
            "bad actor type": corrupt(DEFAULTED_PDU, 16, 9),
            "bad actor length": corrupt(DEFAULTED_PDU, 17, 0xFF),
            "marker subtype": corrupt(DEFAULTED_PDU, 14, 2),
        }
        for name, frame in cases.items():
            with self.subTest(name):
                self.start("-d -t 0")
                for _ in range(3):
                    self.switch.link.send(frame)
                    time.sleep(0.5)
                time.sleep(2)
                self.assertEqual(self.count(TAKEN), 0)
                self.assert_running_clean()

        cases = {
            "short": host[:40],
            "truncated partner": pad(host[:40]),
            "bad partner type": corrupt(host, 36, 9),
            "bad partner length": corrupt(host, 37, 0xFF),
        }
        for name, frame in cases.items():
            with self.subTest(name, taken_over=True):
                self.start("-d -t 0")
                self.take_over()
                self.switch.pdu = None
                mark = self.journal.mark()
                for _ in range(3):
                    self.switch.link.send(frame)
                    time.sleep(0.5)
                time.sleep(2)
                self.assertEqual(self.count(BACK, mark), 0)
                self.assert_running_clean()

    def test_lacp_takeover_partner_only(self) -> None:
        self.start("-d -t 0")
        self.take_over()
        self.assert_taken_over()
        self.assertEqual(self.count(r"watchdog"), 1)
        self.assert_running_clean()

    def test_lacp_handback_partner_only(self) -> None:
        self.start("-d -t 0")
        self.take_over()
        self.switch.pdu = partner_pdu(HOST_MAC)
        self.wait(BACK)
        self.assert_handed_back()
        self.assert_running_clean()

    def test_zz_lacp_flood(self) -> None:
        # Runs last: on PHY-attached ftgmac100 NICs this can deadlock the guest kernel.
        self.start("-d -t 0")
        host = partner_pdu(HOST_MAC)
        for i in range(200):
            self.switch.link.send(DEFAULTED_PDU if i % 2 == 0 else host)
            time.sleep(0.002)
        self.switch.pdu = host
        last = -1
        while (n := self.count(f"{TAKEN}|{BACK}")) != last:
            last = n
            time.sleep(5)
        self.assertGreater(self.count(TAKEN), 1)
        self.assertGreater(self.count(BACK), 1)
        self.assert_running_clean()
        self.assert_handed_back()
        self.take_over()
        self.assert_taken_over()

    def test_lacp_ncsi_mac_change(self) -> None:
        old, new = self.eth1_mac(), "02:00:00:00:00:99"
        self.addCleanup(self.vm.run, f"systemctl stop lacp-takeoverd\n{CLEANUP}\n{set_mac(old)}\n{CLEANUP}")
        self.start("-d -t 0")
        self.vm.run(f"{set_mac(new)}\n{CLEANUP}")
        self.switch.pdu = partner_pdu(mac(new))
        self.wait(rf"(?i)LACPDU: partner {new} \(bmc\)")
        self.switch.pdu = partner_pdu(mac(old))
        self.wait(rf"(?i)LACPDU: partner {old} \(host\)")

        self.take_over()
        self.assert_taken_over()
        self.assertEqual(mac_str(self.bmc_pdus(self.t0)[-1][20:26]), new)
        mark = self.journal.mark()
        self.switch.pdu = partner_pdu(mac(new))
        self.wait(rf"(?i)LACPDU: partner {new} \(bmc\)", since=mark)
        time.sleep(3)
        self.assertEqual(self.count(BACK, mark), 0)
        self.switch.pdu = partner_pdu(mac(old))
        self.wait(BACK, since=mark)
        self.assert_handed_back()
        self.assert_running_clean()

    # Watchdog

    def test_watchdog_t0_uses_default_timeout(self) -> None:
        self.start("-d -t 0")
        self.take_over()
        i, t = self.reset()
        self.wait(BACK, since=i)
        j, expired = self.wait(r"watchdog expired", 10, i)
        self.wait(TAKEN, since=j)
        self.assertAlmostEqual(expired - t, 4, delta=0.5)

    def test_watchdog_reset(self) -> None:
        self.start("-d -t 6")
        self.switch.pdu = DEFAULTED_PDU
        for _ in range(6):
            i, t = self.reset(6)
            time.sleep(2)
        self.assertEqual(self.count(TAKEN), 0)
        j, expired = self.wait(r"watchdog expired", 10, i)
        self.wait(TAKEN, since=j)
        self.assertAlmostEqual(expired - t, 6, delta=0.5)

    def test_watchdog_set_timeout(self) -> None:
        self.start("-d")
        self.switch.pdu = DEFAULTED_PDU
        self.reset()
        i, t = self.wd_send(SET_TIMEOUT, struct.pack("!I", 8), r"watchdog timeout set to 8s")
        j, expired = self.wait(r"watchdog expired", 15, i)
        self.wait(TAKEN, since=j)
        self.assertAlmostEqual(expired - t, 8, delta=0.5)
        i, t = self.reset(8)
        self.wait(BACK, since=i)

    def test_watchdog_set_timeout_zero(self) -> None:
        self.start("-d -t 8")
        self.switch.pdu = DEFAULTED_PDU
        self.reset(8)
        i, _ = self.wd_send(SET_TIMEOUT, struct.pack("!I", 0), r"watchdog disabled")
        self.wait(TAKEN, 5, i)
        i, t = self.reset(4)
        self.wait(BACK, since=i)
        j, expired = self.wait(r"watchdog expired", 10, i)
        self.wait(TAKEN, since=j)
        self.assertAlmostEqual(expired - t, 4, delta=0.5)

    def test_watchdog_disable(self) -> None:
        self.start("-d")
        self.switch.pdu = DEFAULTED_PDU
        self.reset()
        i, _ = self.wd_send(DISABLE, expect=r"watchdog disabled")
        self.wait(TAKEN, 5, i)
        time.sleep(6)
        self.assertEqual(self.count(r"watchdog expired", i), 0)
        self.assertEqual(self.count(BACK, i), 0)
        self.assert_taken_over()

    def test_watchdog_takeover_only(self) -> None:
        self.start("-d")
        self.switch.pdu = DEFAULTED_PDU
        i, t = self.reset()
        _, taken = self.wait(r"taking over:", since=i)
        self.assertAlmostEqual(taken - t, 4, delta=0.5)
        self.wait(TAKEN, since=i)
        self.assert_taken_over()
        self.assert_running_clean()

    def test_watchdog_handback_only(self) -> None:
        self.start("-d -t 0")
        self.take_over()
        i, _ = self.reset()
        self.wait(BACK, since=i)
        self.assert_handed_back()
        self.assert_running_clean()

    def test_watchdog_bad_messages(self) -> None:
        self.start("-d -t 6")
        self.switch.pdu = DEFAULTED_PDU
        self.reset(6)
        cases = {
            "bad op": (struct.pack("!BI", 9, 0), r"unexpected payload size for op unknown|invalid watchdog op code"),
            "bad length": (struct.pack("!BI", RESET, 4) + bytes(4), r"unexpected payload size for op reset: 4"),
            "missing timeout": (struct.pack("!BI", SET_TIMEOUT, 4), r"missing watchdog timeout"),
        }
        for name, (msg, log) in cases.items():
            with self.subTest(name):
                bad = self.watchdog()
                mark = self.journal.mark()
                bad.sock.sendall(msg)
                self.wait(log, 10, mark)
                bad.sock.settimeout(10)
                try:
                    self.assertEqual(bad.sock.recv(1), b"")
                except ConnectionResetError:
                    pass
                self.reset(6)
        self.assertEqual(self.count(TAKEN), 0)
        self.assertEqual(self.vm.run("systemctl is-active lacp-takeoverd").strip(), "active")

    def test_watchdog_host_reboot(self) -> None:
        self.start("-d")
        self.switch.pdu = DEFAULTED_PDU
        # Each reboot leaves the previous connection open and silent.
        for _ in range(12):
            self.wds.insert(0, Watchdog(self.wd_port))
            self.reset()
        for _ in range(3):
            time.sleep(1.5)
            self.reset()
        self.assertEqual(self.count(TAKEN), 0)

    def test_watchdog_connection_dos(self) -> None:
        dropin = "/run/systemd/system/lacp-takeoverd.service.d"
        self.addCleanup(self.vm.run, f"rm -rf {dropin}; systemctl daemon-reload")
        self.start("-d", prep=f"mkdir -p {dropin} && printf '[Service]\\nLimitNOFILE=64\\n' > {dropin}/nofile.conf "
                              "&& systemctl daemon-reload")
        self.switch.pdu = DEFAULTED_PDU
        self.reset()
        mark = self.journal.mark()
        stop = threading.Event()

        def keep_resetting() -> None:
            while not stop.wait(1):
                self.wds[0].send(RESET)

        resetter = threading.Thread(target=keep_resetting)
        resetter.start()
        try:
            flood = [socket.create_connection(("127.0.0.1", self.wd_port)) for _ in range(100)]
            for s in flood[:4]:
                s.send(b"\0")
            time.sleep(5)
            for s in flood:
                s.close()
        finally:
            stop.set()
            resetter.join()
        self.assertEqual(self.count(TAKEN), 0)
        self.assertGreaterEqual(self.count(r"watchdog reset", mark), 5)
        self.assertEqual(self.count(r"Too many open files", mark), 0)
        self.wds[0].close()
        self.wds = []
        time.sleep(2)
        self.reset()
        self.assertEqual(self.vm.run("systemctl is-active lacp-takeoverd").strip(), "active")


if __name__ == "__main__":
    unittest.main(verbosity=2)
