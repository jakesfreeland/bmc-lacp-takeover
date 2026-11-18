# VM tests

Two `unittest` suites (Python 3.10+, standard library only) that boot QEMU
guests and play the network peers of each daemon:

* `test_takeoverd.py`: lacp-takeoverd in an OpenBMC AST2600 EVB guest
  (`qemu-system-arm -M ast2600-evb`). The runner plays the LACP switch on the
  NCSI interface and the host watchdog client.
* `test_watchdogd.py`: lacp-watchdogd in a FreeBSD 16.0-CURRENT guest
  (`qemu-system-x86_64`). The runner plays the BMC watchdog server and the
  default gateways.

The runner exchanges raw Ethernet frames with each guest NIC through QEMU's
`dgram` netdev over unix sockets, so no root, tap devices or libpcap are
needed.

## Requirements

* `qemu-system-arm`, `qemu-system-x86_64` (QEMU 7.2+) and OVMF
  (`sudo apt install qemu-system-arm qemu-system-x86 ovmf`)
* `ssh`, `ssh-keygen`, `tar`
* The [Yocto build host packages](https://docs.yoctoproject.org/ref-manual/system-requirements.html)
  for the OpenBMC image

KVM is used for the FreeBSD guest when `/dev/kvm` is accessible. Without it
the guest still works, just slower.

## Build directory

Images, downloads and the generated SSH key go in `$BUILD_DIR` (default
`tests/build`). An OpenBMC build needs about 100 GB, so you may want to point
it somewhere else, e.g. `export BUILD_DIR=~/Builds/lacp-takeover`.

## Running

```sh
./build-openbmc.sh          # once, and after changing lacp-takeoverd (incremental)
./test_takeoverd.py
./test_watchdogd.py         # downloads and prepares the FreeBSD image on first run
```

Run a single test with e.g. `./test_takeoverd.py TakeoverdTests.test_takeover`.

`build-openbmc.sh` builds `obmc-phosphor-image` for the `canopy-qemu` machine
from the `openbmc` submodule (canopybmc) with `meta-lacp-test`, which adds
lacp-takeoverd from this tree, the systemd-networkd configuration for eth0,
eth1 and bond0, and the test SSH key.

The FreeBSD image is configured once over the serial console (static
addresses, sshd, SSH key). Each run boots it with `-snapshot`, copies in the
sources, builds lacp-watchdogd and installs its rc script. Delete
`$BUILD_DIR/freebsd/freebsd-lacp-test.qcow2` to prepare it again.
