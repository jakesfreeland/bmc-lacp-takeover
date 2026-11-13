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
	unsigned char data[16];	/* address in network byte order */
};

/*
 * Get up to max non-link-local IPv4/IPv6 addresses of an interface, returning
 * the count or -1 on error.
 *   ifname: interface name
 *   a:      output addresses
 *   max:    capacity of a
 */
int addrs(const char *ifname, struct addr *a, int max);

/*
 * Get up to max default gateways from the main routing table, returning the
 * count or -1 on error.
 *   nlfd:   NETLINK_ROUTE socket
 *   family: AF_INET, AF_INET6 or AF_UNSPEC for both
 *   if_idx: output interface index, or 0 for any
 *   g:      output gateways
 *   max:    capacity of g
 */
int gateways(int nlfd, int family, int if_idx, struct addr *g, int max);

/*
 * Bring an interface up or down, returning 0 or -1 on error.
 *   nlfd: NETLINK_ROUTE socket
 *   idx:  interface index
 *   up:   IFF_UP to bring up, 0 to bring down
 */
int set_link(int nlfd, int idx, unsigned int up);

/*
 * Set a link attribute on an interface, returning 0 or -1 on error.
 *   nlfd: NETLINK_ROUTE socket
 *   idx:  interface index
 *   type: IFLA_* attribute type
 *   data: attribute value
 *   len:  length of data
 */
int set_link_attr(int nlfd, int idx, int type, const void *data, int len);

/*
 * Add or delete addresses on an interface, returning 0 or -1 on error.
 *   nlfd: NETLINK_ROUTE socket
 *   type: RTM_NEWADDR or RTM_DELADDR
 *   idx:  interface index
 *   a:    addresses
 *   n:    number of addresses
 */
int set_addrs(int nlfd, int type, int idx, struct addr *a, int n);

/*
 * Add default routes via gateways out an interface, returning 0 or -1 on error.
 *   nlfd: NETLINK_ROUTE socket
 *   idx:  output interface index
 *   g:    gateways
 *   n:    number of gateways
 */
int add_routes(int nlfd, int idx, struct addr *g, int n);
