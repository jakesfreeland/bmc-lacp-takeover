/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#pragma once

struct addr {
	int family;		/* AF_INET or AF_INET6 */
	int len;		/* length of data: 4 or 16 */
	int prefix;		/* prefix length, unused for gateways */
	int metric;		/* route metric, unused for addresses */
	unsigned char data[16];	/* address in network byte order */
};

/*
 * Get the non-link-local IPv4/IPv6 addresses of an interface, returning the
 * count or -1 on error.
 *   ifname: interface name
 *   a:      output addresses, to be freed by the caller
 */
int addrs(const char *ifname, struct addr **a);

/*
 * Get the default gateways from the main routing table, returning the count or
 * -1 on error.
 *   nlfd:   NETLINK_ROUTE socket
 *   family: AF_INET, AF_INET6 or AF_UNSPEC for both
 *   ifname: output interface name, or NULL for any
 *   g:      output gateways, to be freed by the caller
 */
int gateways(int nlfd, int family, const char *ifname, struct addr **g);
