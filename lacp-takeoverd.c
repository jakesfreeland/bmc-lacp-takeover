/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timerfd.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

#include "lacp-pdu.h"
#include "lacp-watchdog.h"
#include "net-common.h"

/* Filter for IEEE 802.3 Slow - LACP keepalive. */
#define	SLOW_FILTER	"ether proto 0x8809 and ether[14] == 1"

/* D-Bus name for systemd-networkd service. */
#define	NETWORK1	"org.freedesktop.network1"

/* Maximum back-to-back reset fails before giving up. */
#define	MAX_B2B_FAILS	2

/* Maximum concurrent watchdog connections. */
#define	MAX_CONNS	8

#define	dbgprintf(...)	do { if (DEBUG) printf(__VA_ARGS__); } while (0)

static const char *NCSI_IFNAME = "eth1";
static const char *BOND_IFNAME = "bond0";
static bool DEBUG;

enum lacp_partner {
	HOST,
	BMC,
	NONE,
};

static const char *
lacp_partner_str(enum lacp_partner partner) {
	switch (partner) {
	case HOST:
		return "host";
	case BMC:
		return "bmc";
	case NONE:
		return "none";
	default:
		return "unknown";
	}
}

[[noreturn]] static void
usage()
{
	fprintf(stderr, "Usage: lacp-takeoverd [OPTIONS]\n"
	    "Take over LACP channel upon host inactivity\n\n"
	    "OPTIONS:\n"
	    "  -b BOND_IFNAME \t LACP bond interface name (%s)\n"
	    "  -d \t\t\t Enable debug logging\n"
	    "  -h \t\t\t Display this help message\n"
	    "  -i NCSI_IFNAME \t NCSI interface name (%s)\n"
	    "  -l ADDR \t\t Host watchdog listen address (%s)\n"
	    "  -p PORT \t\t Host watchdog listen port (%hu)\n"
	    "  -t TIMEOUT \t\t Host watchdog expiration timeout (%us)\n",
	    BOND_IFNAME, NCSI_IFNAME, DEF_WATCHDOG_ADDR, DEF_WATCHDOG_PORT,
	    DEF_WATCHDOG_TIMO_SEC);
	exit(EXIT_FAILURE);
}

static int
handback(int nlfd)
{
	struct addr addr[8], gw[4];
	int naddr, ngw;
	unsigned int bond_idx, ncsi_idx;

	ncsi_idx = if_nametoindex(NCSI_IFNAME);
	if (ncsi_idx == 0) {
		warn("if_nametoindex(%s)", NCSI_IFNAME);
		return -1;
	}
	bond_idx = if_nametoindex(BOND_IFNAME);
	if (bond_idx == 0) {
		warn("if_nametoindex(%s)", BOND_IFNAME);
		return -1;
	}

	naddr = addrs(BOND_IFNAME, addr, 8);
	ngw = gateways(nlfd, AF_UNSPEC, bond_idx, gw, 4);
	if (naddr < 0 || ngw < 0)
		return -1;
	dbgprintf("handing back: releasing %s from %s with %d addresses and %d gateways\n",
	    NCSI_IFNAME, BOND_IFNAME, naddr, ngw);

	if (set_addrs(nlfd, RTM_DELADDR, bond_idx, addr, naddr) ||
	    set_link(nlfd, bond_idx, 0) ||
	    set_link_attr(nlfd, ncsi_idx, IFLA_MASTER, &(int){ 0 }, sizeof(int)) ||
	    set_link(nlfd, ncsi_idx, IFF_UP) ||
	    set_addrs(nlfd, RTM_NEWADDR, ncsi_idx, addr, naddr) ||
	    add_routes(nlfd, ncsi_idx, gw, ngw))
		return -1;
	return 0;
}

static int
takeover(int nlfd)
{
	struct addr addr[8], gw[4];
	struct ifreq ifr = { };
	int naddr, ngw;
	unsigned int bond_idx, ncsi_idx;

	ncsi_idx = if_nametoindex(NCSI_IFNAME);
	if (ncsi_idx == 0) {
		warn("if_nametoindex(%s)", NCSI_IFNAME);
		return -1;
	}
	bond_idx = if_nametoindex(BOND_IFNAME);
	if (bond_idx == 0) {
		warn("if_nametoindex(%s)", BOND_IFNAME);
		return -1;
	}

	naddr = addrs(NCSI_IFNAME, addr, 8);
	ngw = gateways(nlfd, AF_UNSPEC, ncsi_idx, gw, 4);
	if (naddr < 0 || ngw < 0)
		return -1;
	dbgprintf("taking over: enslaving %s to %s with %d addresses and %d gateways\n",
	    NCSI_IFNAME, BOND_IFNAME, naddr, ngw);

	strncpy(ifr.ifr_name, NCSI_IFNAME, sizeof(ifr.ifr_name) - 1);
	if (ioctl(nlfd, SIOCGIFHWADDR, &ifr)) {
		warn("ioctl(SIOCGIFHWADDR, %s)", NCSI_IFNAME);
		return -1;
	}

	if (set_addrs(nlfd, RTM_DELADDR, ncsi_idx, addr, naddr) ||
	    set_link(nlfd, ncsi_idx, 0) ||
	    set_link_attr(nlfd, bond_idx, IFLA_ADDRESS, ifr.ifr_hwaddr.sa_data, ETH_ALEN) ||
	    set_link_attr(nlfd, ncsi_idx, IFLA_MASTER, &bond_idx, sizeof(bond_idx)) ||
	    set_link(nlfd, bond_idx, IFF_UP) ||
	    set_addrs(nlfd, RTM_NEWADDR, bond_idx, addr, naddr) ||
	    add_routes(nlfd, bond_idx, gw, ngw))
		return -1;
	return 0;
}

static void
reconfigure(sd_bus *bus, const char *ifname)
{
	sd_bus_error e = SD_BUS_ERROR_NULL;
	char idx[16], *path, *state;
	int i, r;

	snprintf(idx, sizeof(idx), "%u", if_nametoindex(ifname));
	r = sd_bus_path_encode("/org/freedesktop/network1/link", idx, &path);
	if (r < 0)
		errx(EXIT_FAILURE, "sd_bus_path_encode: %s", strerror(-r));

	r = sd_bus_call_method(bus, NETWORK1, path, NETWORK1 ".Link",
	    "Reconfigure", &e, NULL, "");
	if (r < 0) {
		errx(EXIT_FAILURE, "reconfigure %s: %s", ifname,
		    e.message ?: strerror(-r));
	}

	for (i = 0; i < 10; ++i) {
		r = sd_bus_get_property_string(bus, NETWORK1, path,
		    NETWORK1 ".Link", "AdministrativeState", &e, &state);
		if (r < 0) {
			errx(EXIT_FAILURE, "get %s state: %s", ifname,
			    e.message ?: strerror(-r));
		}
		if (strcmp(state, "configuring") != 0)
			break;
		free(state);
		usleep(100000);
	}

	if (i == 10) {
		warnx("timed out waiting for %s to be reconfigured by "
		    "systemd-networkd", ifname);
	} else {
		if (strcmp(state, "configured") != 0 &&
		    strcmp(state, "unmanaged") != 0) {
			errx(EXIT_FAILURE, "%s is %s after reconfiguration",
			     ifname, state);
		}
		free(state);
	}

	free(path);
}

static void
reset(sd_bus *bus)
{
	warnx("restoring %s and %s to their systemd-networkd configuration",
	    BOND_IFNAME, NCSI_IFNAME);
	reconfigure(bus, BOND_IFNAME);
	reconfigure(bus, NCSI_IFNAME);
}

static bool
enslaved(void)
{
	char path[PATH_MAX], target[PATH_MAX];
	const char *name;
	ssize_t len;

	snprintf(path, sizeof(path), "/sys/class/net/%s/master", NCSI_IFNAME);
	len = readlink(path, target, sizeof(target) - 1);
	if (len < 0) {
		if (errno != ENOENT)
			warn("readlink(%s)", path);
		return false;
	}
	target[len] = '\0';
	name = strrchr(target, '/');
	return strcmp(name ? name + 1 : target, BOND_IFNAME) == 0;
}

static enum lacp_partner
get_switch_partner(int nlfd, const struct lacp_frame *frame)
{
	struct ifreq ifr = { };

	/*
	 * eth1's backing MAC can change at any time depending on the polarity
	 * of the NCSI_MUX_SEL SGPIO. Do not cache eth1's address.
	 */
	strncpy(ifr.ifr_name, NCSI_IFNAME, sizeof(ifr.ifr_name) - 1);
	if (ioctl(nlfd, SIOCGIFHWADDR, &ifr))
		err(EXIT_FAILURE, "ioctl(SIOCGIFHWADDR, %s)", NCSI_IFNAME);

	if ((frame->actor.state & LACP_STATE_DEFAULTED) != 0)
		return NONE;
	if (memcmp(frame->partner.sys_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN) == 0)
		return BMC;
	return HOST;
}

static const char *
fmt_mac(const unsigned char *mac)
{
	static char mac_str[18];

	snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return mac_str;
}

static int
read_lacp_pdu(int nlfd, pcap_t *pcap, enum lacp_partner *partner)
{
	struct pcap_pkthdr *h;
	int n;
	const unsigned char *data;
	const struct lacp_frame *frame;

	n = pcap_next_ex(pcap, &h, &data);
	if (n == PCAP_ERROR) {
		warnx("pcap_next_ex(%s): %s", NCSI_IFNAME, pcap_geterr(pcap));
		return -1;
	}
	if (n != 1)
		return -1;

	if (h->caplen < sizeof(*frame)) {
		dbgprintf("ignoring short frame (%u bytes)\n", h->caplen);
		return -1;
	}

	frame = (const struct lacp_frame *)data;
	if (frame->actor.tlv_type != LACP_TLV_ACTOR ||
	    frame->actor.tlv_len != sizeof(frame->actor) ||
	    frame->partner.tlv_type != LACP_TLV_PARTNER ||
	    frame->partner.tlv_len != sizeof(frame->partner)) {
		dbgprintf("ignoring malformed LACPDU\n");
		return -1;
	}

	*partner = get_switch_partner(nlfd, frame);
	dbgprintf("LACPDU: partner %s (%s)\n",
		fmt_mac(frame->partner.sys_mac), lacp_partner_str(*partner));
	return 0;
}

int
main(int argc, char *argv[])
{
	struct bpf_program prog;
	struct epoll_event ev = { .events = EPOLLIN };
	struct itimerspec its = { .it_value.tv_sec = DEF_WATCHDOG_TIMO_SEC };
	struct packet_mreq mr = {
		.mr_type = PACKET_MR_MULTICAST,
		.mr_alen = ETH_ALEN,
		.mr_address = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x02 },
	};
	struct sockaddr_in waddr = {
		.sin_family = AF_INET,
		.sin_port = htons(DEF_WATCHDOG_PORT),
	};
	sigset_t mask;
	sd_bus *bus;
	pcap_t *pcap;
	enum lacp_partner partner = HOST;
	int b2b_fails = 0, cfd, efd, nconns = 0, nlfd, opt, pfd, r, sfd, tfd, wfd;
	const char *watchdog_addr = DEF_WATCHDOG_ADDR;
	char errbuf[PCAP_ERRBUF_SIZE];
	bool host_active;

	setlinebuf(stdout);

	while ((opt = getopt(argc, argv, ":b:dhi:l:p:t:")) != -1) {
		switch (opt) {
		case 'b':
			if (strlen(optarg) >= IFNAMSIZ) {
				errx(EXIT_FAILURE,
				     "invalid bond interface name: %s", optarg);
			}
			BOND_IFNAME = optarg;
			break;
		case 'd':
			DEBUG = true;
			break;
		case 'h':
			usage();
		case 'i':
			if (strlen(optarg) >= IFNAMSIZ) {
				errx(EXIT_FAILURE,
				     "invalid NCSI interface name: %s", optarg);
			}
			NCSI_IFNAME = optarg;
			break;
		case 'l':
			watchdog_addr = optarg;
			break;
		case 'p':
			errno = 0;
			waddr.sin_port = htons(strtoul(optarg, NULL, 0));
			if (errno != 0)
				err(EXIT_FAILURE, "invalid port: %s", optarg);
			break;
		case 't':
			errno = 0;
			its.it_value.tv_sec = strtol(optarg, NULL, 0);
			if (errno != 0 || its.it_value.tv_sec < 0)
				err(EXIT_FAILURE, "invalid timeout: %s", optarg);
			break;
		case ':':
			warnx("missing argument for option -%c", optopt);
			usage();
		case '?':
			warnx("unknown option: -%c", optopt);
			/* FALLTHROUGH */
		default:
			usage();
		}
	}

	nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlfd < 0)
		err(EXIT_FAILURE, "socket(AF_NETLINK)");

	r = sd_bus_open_system(&bus);
	if (r < 0)
		errx(EXIT_FAILURE, "sd_bus_open_system: %s", strerror(-r));

	/*
	 * Disable watchdog on startup if a timeout of zero is passed.
	 * It can be enabled by sending a RESET.
	 */
	host_active = its.it_value.tv_sec != 0;

	if (enslaved()) {
		warnx("started with %s enslaved to %s", NCSI_IFNAME,
		    BOND_IFNAME);
		reset(bus);
	}

	wfd = socket(AF_INET, SOCK_STREAM, 0);
	if (wfd < 0)
		err(EXIT_FAILURE, "socket");

	r = inet_pton(AF_INET, watchdog_addr, &waddr.sin_addr);
	if (r == 0)
		errx(EXIT_FAILURE, "invalid address string: %s", watchdog_addr);
	else if (r < 0)
		err(EXIT_FAILURE, "inet_pton");

	if (setsockopt(wfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
		err(EXIT_FAILURE, "setsockopt(SO_REUSEADDR)");

	if (bind(wfd, (struct sockaddr *)&waddr, sizeof(waddr)) < 0)
		err(EXIT_FAILURE, "bind");

	if (listen(wfd, 1) < 0)
		err(EXIT_FAILURE, "listen");

	pcap = pcap_create(NCSI_IFNAME, errbuf);
	if (pcap == NULL)
		errx(EXIT_FAILURE, "pcap_create(%s): %s", NCSI_IFNAME, errbuf);

	if (pcap_set_immediate_mode(pcap, 1) != 0)
		errx(EXIT_FAILURE, "pcap_set_immediate_mode(%s)", NCSI_IFNAME);

	if (pcap_activate(pcap) != 0) {
		errx(EXIT_FAILURE, "pcap_activate(%s): %s", NCSI_IFNAME,
		    pcap_geterr(pcap));
	}

	/* Receive LACPDUs even when the NIC filters multicast. */
	mr.mr_ifindex = if_nametoindex(NCSI_IFNAME);
	if (setsockopt(pcap_fileno(pcap), SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
	    sizeof(mr)) < 0)
		err(EXIT_FAILURE, "setsockopt(PACKET_ADD_MEMBERSHIP, %s)", NCSI_IFNAME);

	if (pcap_setdirection(pcap, PCAP_D_IN) != 0) {
		errx(EXIT_FAILURE, "pcap_setdirection(%s): %s", NCSI_IFNAME,
		    pcap_geterr(pcap));
	}

	if (pcap_compile(pcap, &prog, SLOW_FILTER, 1, PCAP_NETMASK_UNKNOWN) != 0) {
		errx(EXIT_FAILURE, "pcap_compile(%s): %s", NCSI_IFNAME,
		    pcap_geterr(pcap));
	}

	if (pcap_setfilter(pcap, &prog) != 0) {
		errx(EXIT_FAILURE, "pcap_setfilter(%s): %s", NCSI_IFNAME,
		    pcap_geterr(pcap));
	}

	if (pcap_setnonblock(pcap, 1, errbuf) != 0) {
		errx(EXIT_FAILURE, "pcap_setnonblock(%s): %s", NCSI_IFNAME,
		    errbuf);
	}

	pfd = pcap_get_selectable_fd(pcap);
	if (pfd < 0)
		errx(EXIT_FAILURE, "pcap_get_selectable_fd(%s)", NCSI_IFNAME);

	tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tfd < 0)
		err(EXIT_FAILURE, "timerfd_create");

	if (timerfd_settime(tfd, 0, &its, NULL) < 0)
		err(EXIT_FAILURE, "timerfd_settime");

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	if (sigprocmask(SIG_BLOCK, &mask, NULL))
		err(EXIT_FAILURE, "sigprocmask");

	sfd = signalfd(-1, &mask, 0);
	if (sfd < 0)
		err(EXIT_FAILURE, "signalfd");

	efd = epoll_create1(0);
	if (efd < 0)
		err(EXIT_FAILURE, "epoll_create1");

	ev.data.fd = sfd;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &ev))
		err(EXIT_FAILURE, "epoll_ctl(signalfd)");
	ev.data.fd = pfd;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, pfd, &ev))
		err(EXIT_FAILURE, "epoll_ctl(pcap)");
	ev.data.fd = wfd;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, wfd, &ev))
		err(EXIT_FAILURE, "epoll_ctl(watchdog)");
	ev.data.fd = tfd;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, tfd, &ev))
		err(EXIT_FAILURE, "epoll_ctl(timerfd)");

	dbgprintf("listening for watchdog messages on %s:%hu\n", watchdog_addr,
	    ntohs(waddr.sin_port));

	for (;;) {
		bool owned;

		if (epoll_wait(efd, &ev, 1, -1) < 0) {
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "epoll_wait");
		}

		if (ev.data.fd == sfd) {
			dbgprintf("received signal, exiting\n");
			break;
		} else if (ev.data.fd == pfd) {
			(void)read_lacp_pdu(nlfd, pcap, &partner);
		} else if (ev.data.fd == wfd) {
			cfd = accept(wfd, NULL, NULL);
			if (cfd < 0) {
				warn("accept");
				continue;
			}
			if (nconns == MAX_CONNS) {
				dbgprintf("too many watchdog connections, dropping new one\n");
				close(cfd);
				continue;
			}
			nconns++;
			ev.events = EPOLLIN;
			ev.data.fd = cfd;
			if (epoll_ctl(efd, EPOLL_CTL_ADD, cfd, &ev))
				err(EXIT_FAILURE, "epoll_ctl(connection)");
		} else if (ev.data.fd == tfd) {
			uint64_t expr;

			/* Watchdog timed out. */
			dbgprintf("watchdog expired\n");
			host_active = false;
			if (read(tfd, &expr, sizeof(expr)) < 0)
				err(EXIT_FAILURE, "read");
		} else /* connection fd */ {
			struct watchdog_msg wm;
			ssize_t ret;
			uint32_t timeout;

			/*
			 * Messages are sent in one segment. Do not wait for
			 * partial ones, it would stall the event loop.
			 */
			ret = recv(ev.data.fd, &wm, sizeof(wm), MSG_DONTWAIT);
			if (ret != sizeof(wm)) {
				if (ret < 0) {
					warn("read(%d): failed to read watchdog message",
					     ev.data.fd);
				}
				close(ev.data.fd);
				nconns--;
				continue;
			}

			wm.wm_len = ntohl(wm.wm_len);
			if (!wm_op_len_verify(wm.wm_op, wm.wm_len)) {
				warnx("unexpected payload size for op %s: %u",
				      wm_op_str(wm.wm_op), wm.wm_len);
				close(ev.data.fd);
				nconns--;
				continue;
			}

			switch (wm.wm_op) {
			case RESET:
				host_active = true;
				if (its.it_value.tv_sec == 0)
					its.it_value.tv_sec = DEF_WATCHDOG_TIMO_SEC;
				if (timerfd_settime(tfd, 0, &its, NULL) < 0)
					err(EXIT_FAILURE, "timerfd_settime");
				dbgprintf("watchdog reset (timeout %lds)\n",
				    (long)its.it_value.tv_sec);
				break;
			case SET_TIMEOUT:
				if (recv(ev.data.fd, &timeout, sizeof(timeout),
				    MSG_DONTWAIT) != sizeof(timeout)) {
					warnx("recv(%d): missing watchdog timeout",
					    ev.data.fd);
					close(ev.data.fd);
					nconns--;
					continue;
				}
				its.it_value.tv_sec = ntohl(timeout);
				dbgprintf("watchdog timeout set to %lds\n",
				    (long)its.it_value.tv_sec);
				if (its.it_value.tv_sec != 0) {
					if (host_active &&
					    timerfd_settime(tfd, 0, &its, NULL) < 0)
						err(EXIT_FAILURE, "timerfd_settime");
					break;
				}
				/* FALLTHROUGH */
			case DISABLE:
				/* Fall back to LACP partner detection alone. */
				host_active = false;
				if (timerfd_settime(tfd, 0, &(struct itimerspec){ }, NULL) < 0)
					err(EXIT_FAILURE, "timerfd_settime");
				dbgprintf("watchdog disabled\n");
				break;
			default:
				warnx("read(%d): invalid watchdog op code: %hhu",
				    ev.data.fd, wm.wm_op);
				close(ev.data.fd);
				nconns--;
				continue;
			}
		}

		owned = enslaved();
		if ((partner == HOST || host_active) && owned) {
			if (handback(nlfd) == 0) {
				printf("LACP bundle restored to the host\n");
				b2b_fails = 0;
				continue;
			}
			warnx("failed to hand back LACP");
		} else if (partner == NONE && !host_active && !owned) {
			if (takeover(nlfd) == 0) {
				printf("took over LACP on %s\n", NCSI_IFNAME);
				b2b_fails = 0;
				continue;
			}
			warnx("failed to take over LACP");
		} else {
			continue;
		}

		if (++b2b_fails > MAX_B2B_FAILS) {
			errx(EXIT_FAILURE, "giving up after exceeding maximum "
			     "failures: %d", MAX_B2B_FAILS);
		}
		reset(bus);
	}

	if (enslaved())
		warnx("exiting with LACP ownership");

	return EXIT_SUCCESS;
}
