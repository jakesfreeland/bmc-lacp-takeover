# bmc-lacp-takeover

Facilitate LACP channel takeover on the BMC when the host is inactive.

## The NC-SI and LACP Problem

On BMCs configured to use NC-SI, traffic destined for the BMC is routed through
a NIC that is shared with the host. When that NIC is also configured for IEEE
802.3ad LACP, the BMC depends on the host maintaining the LACP channel to keep
data flowing in and out of the NC-SI NIC.

In the event that the host stops maintaining the LACP channel (because it
powered off, kernel panicked, etc.), the upstream switch will disable the
channel. If the switch isn't configured to fall back to the NC-SI NIC on
channel dissolution, all non-LACP traffic destined for the NC-SI NIC will be
dropped. Since the BMC is connected to the outside via this port, all ssh and
web sessions with the BMC will be inaccessible.

## lacp-takeoverd

The BMC's primary purpose is out-of-band management, so it is imperative that
it stays accessible when the host is not. Fix this issue by taking over the
LACP channel when the host goes down.

The lacp-takeover daemon is responsible for executing the LACP takeover. It
regularly monitors LACP packets from the switch and watchdog resets from the
host. When all of the following conditions are met, lacp-takeoverd will
initiate its takeover:

1. An LACP packet from the upstream switch contains the *defaulted bit* (bit 6
   in LACPDU actor state field). This indicates that the switch has fallen back
   to its default operational partner configuration.
2. The lacp-takeoverd watchdog timer fired due to host inactivity.

Combined, these conditions validate that the host is no longer alive from the
perspective of the switch and the BMC. In this case, we can be certain that
taking over the LACP channel will not disrupt regular host operations.

If, at any time, the BMC receives an LACP PDU or watchdog reset that suggests
the host is alive, then lacp-takeoverd will relinquish its ownership of the
LACP channel.

## lacp-watchdogd

The lacp-watchdog daemon runs on the host and periodically resets the watchdog
managed by lacp-takeoverd. Watchdog resets are only sent when the host has
external network connectivity, even if the host is otherwise fully
functional. If the watchdog is not reset before its timeout, then the BMC will
mark the host as inactive and prepare for LACP takeover. See the
[lacp-takeoverd](#lacp-takeoverd) section for all LACP takeover conditions.

## Compatibility

### Compilation

* A compiler that supports `-std=gnu23`
* libsystemd (for lacp-takeoverd)
* libpcap (for lacp-takeoverd)

### On the BMC

* Linux (with `CONFIG_BONDING` configuration option)
* Interfaces managed by systemd-networkd

### On the host

* POSIX compliant environment
* netlink socket support
