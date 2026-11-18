/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#include <sys/socket.h>
#include <sys/time.h>

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#else
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#endif

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lacp-watchdog.h"
#include "net-common.h"

/* Default watchdog reset period. */
#define	RESET_PERIOD_SEC	(DEF_WATCHDOG_TIMO_SEC / 4)

/* Maximum amount of time to wait for gateway response. */
#define	RECV_TIMO_USEC		(RESET_PERIOD_SEC * 1000000 / 2)

/* Sleep time between watchdog connect attempts. */
#define	CONNECT_SLEEP_SEC	1

#define	dbgprintf(...)	do { if (DEBUG) printf(__VA_ARGS__); } while (0)

static bool DEBUG;

[[noreturn]] static void
usage()
{
	fprintf(stderr, "Usage: lacp-watchdogd [OPTIONS]\n"
	    "Send watchdog resets to lacp-takeoverd on the BMC\n\n"
	    "OPTIONS:\n"
	    "  -a ADDR \t\t BMC watchdog address (%s)\n"
	    "  -d \t\t\t Enable debug logging\n"
	    "  -h \t\t\t Display this help message\n"
	    "  -i IFACE \t\t Source interface for gateway connectivity check\n"
	    "  -p PORT \t\t BMC watchdog port (%hu)\n"
	    "  -r PERIOD \t\t Watchdog reset period (%us)\n"
	    "  -t TIMEOUT \t\t BMC watchdog expiration timeout\n",
	    DEF_WATCHDOG_ADDR, DEF_WATCHDOG_PORT, RESET_PERIOD_SEC);
	exit(EXIT_FAILURE);
}

static uint16_t
cksum(const void *buf, size_t len)
{
	const uint16_t *p = buf;
	uint32_t sum = 0;

	for (; len > 1; len -= 2)
		sum += *p++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ~sum;
}

static bool
gateway_reachable(int fd, int nlfd, const char *ifname, uint16_t seq)
{
	struct sockaddr_in dst = { .sin_family = AF_INET };
	struct icmp req = { .icmp_type = ICMP_ECHO }, *icmp;
	alignas(struct ip) unsigned char buf[512];
	struct addr *gw;
	struct ip *ip;
	ssize_t n;

	if (gateways(nlfd, AF_INET, ifname, &gw) < 1) {
		dbgprintf("no default gateway found\n");
		free(gw);
		return false;
	}

	memcpy(&dst.sin_addr, gw[0].data, sizeof(dst.sin_addr));
	free(gw);

	req.icmp_id = htons(getpid());
	req.icmp_seq = htons(seq);
	req.icmp_cksum = cksum(&req, ICMP_MINLEN);
	if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0 ||
	    send(fd, &req, ICMP_MINLEN, 0) != ICMP_MINLEN)
		return false;

	for (;;) {
		n = recv(fd, buf, sizeof(buf), 0);
		if (n <= 0)
			return false;
		ip = (struct ip *)buf;
		icmp = (struct icmp *)(buf + ip->ip_hl * 4);
		if (n >= (unsigned char *)icmp + ICMP_MINLEN - buf &&
		    icmp->icmp_type == ICMP_ECHOREPLY &&
		    icmp->icmp_id == req.icmp_id &&
		    icmp->icmp_seq == req.icmp_seq)
			return true;
	}
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in waddr = {
		.sin_family = AF_INET,
		.sin_port = htons(DEF_WATCHDOG_PORT),
	};
	struct watchdog_msg reset = { .wm_op = RESET };
	struct timeval tv = { .tv_usec = RECV_TIMO_USEC };
	struct ifaddrs *ifap, *ifa;
	unsigned int period = RESET_PERIOD_SEC;
	int opt, r, wfd, pfd, nlfd;
	uint32_t timeout = 0;
	uint16_t seq = 0;
	const char *watchdog_addr = DEF_WATCHDOG_ADDR, *ifname = NULL;

	setlinebuf(stdout);

	while ((opt = getopt(argc, argv, ":a:dhi:p:r:t:")) != -1) {
		switch (opt) {
		case 'a':
			watchdog_addr = optarg;
			break;
		case 'd':
			DEBUG = true;
			break;
		case 'h':
			usage();
		case 'i':
			ifname = optarg;
			break;
		case 'p':
			errno = 0;
			waddr.sin_port = htons(strtoul(optarg, NULL, 0));
			if (errno != 0)
				err(EXIT_FAILURE, "invalid port: %s", optarg);
			break;
		case 'r':
			errno = 0;
			period = strtoul(optarg, NULL, 0);
			if (errno != 0 || period == 0)
				err(EXIT_FAILURE, "invalid period: %s", optarg);
			break;
		case 't':
			errno = 0;
			timeout = strtoul(optarg, NULL, 0);
			if (errno != 0)
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
		err(EXIT_FAILURE, "socket(NETLINK_ROUTE)");

	pfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (pfd < 0)
		err(EXIT_FAILURE, "socket(ICMP)");
	if (setsockopt(pfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		err(EXIT_FAILURE, "setsockopt(SO_RCVTIMEO)");

	if (ifname != NULL) {
		if (getifaddrs(&ifap) < 0)
			err(EXIT_FAILURE, "getifaddrs");
		for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr != NULL &&
			    ifa->ifa_addr->sa_family == AF_INET &&
			    strcmp(ifa->ifa_name, ifname) == 0)
				break;
		}
		if (ifa == NULL)
			errx(EXIT_FAILURE, "no IPv4 address on %s", ifname);
		if (bind(pfd, ifa->ifa_addr, sizeof(struct sockaddr_in)) < 0)
			err(EXIT_FAILURE, "bind");
		freeifaddrs(ifap);
	}

	r = inet_pton(AF_INET, watchdog_addr, &waddr.sin_addr);
	if (r == 0)
		errx(EXIT_FAILURE, "invalid address string: %s", watchdog_addr);
	else if (r < 0)
		err(EXIT_FAILURE, "inet_pton");

reconnect:
	for (int i = 0; ; i++) {
		wfd = socket(AF_INET, SOCK_STREAM, 0);
		if (wfd < 0)
			err(EXIT_FAILURE, "socket");

		if (connect(wfd, (struct sockaddr *)&waddr, sizeof(waddr)) == 0) {
			dbgprintf("connected to: %s:%d\n", watchdog_addr,
			    ntohs(waddr.sin_port));
			break;
		}

		close(wfd);
		dbgprintf("connection attempt %d to %s:%d failed (%m), "
		    "retrying in %us\n", i, watchdog_addr,
		    ntohs(waddr.sin_port), CONNECT_SLEEP_SEC);
		sleep(CONNECT_SLEEP_SEC);
	}

	if (timeout != 0) {
		union {
			struct watchdog_msg wm;
			uint8_t pad[sizeof(struct watchdog_msg) + sizeof(timeout)];
		} msg;
		uint32_t ntimeout;

		msg.wm.wm_op = SET_TIMEOUT;
		msg.wm.wm_len = htonl(sizeof(timeout));
		ntimeout = htonl(timeout);
		memcpy(msg.wm.wm_data, &ntimeout, sizeof(ntimeout));
		if (send(wfd, &msg, sizeof(msg), MSG_NOSIGNAL) != sizeof(msg)) {
			warn("send(SET_TIMEOUT)");
			close(wfd);
			goto reconnect;
		}
	}

	for (;;) {
		if (gateway_reachable(pfd, nlfd, ifname, seq++)) {
			if (send(wfd, &reset, sizeof(reset), MSG_NOSIGNAL) != sizeof(reset)) {
				warn("send(RESET)");
				close(wfd);
				goto reconnect;
			}
			dbgprintf("sent watchdog reset\n");
		} else {
			dbgprintf("gateway unreachable, skipping reset\n");
		}
		sleep(period);
	}
}
