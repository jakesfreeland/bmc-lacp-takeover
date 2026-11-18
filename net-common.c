/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#include <sys/socket.h>

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#elifdef __FreeBSD__
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#endif

#include <net/if.h>
#include <netinet/in.h>

#include <err.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "net-common.h"

static unsigned char *
ip(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return (void *)&((struct sockaddr_in *)sa)->sin_addr;
	return (void *)&((struct sockaddr_in6 *)sa)->sin6_addr;
}

/* Append an entry to a, returning it or NULL (freeing a) on error. */
static struct addr *
push(struct addr **a, int *n)
{
	struct addr *p;

	p = realloc(*a, (*n + 1) * sizeof(**a));
	if (p == NULL) {
		warn("realloc");
		free(*a);
		*a = NULL;
		return NULL;
	}
	*a = p;
	return &p[(*n)++];
}

int
addrs(const char *ifname, struct addr **a)
{
	struct ifaddrs *ifa, *i;
	struct addr *p;
	int n = 0, j;

	*a = NULL;
	if (getifaddrs(&ifa)) {
		warn("getifaddrs");
		return -1;
	}
	for (i = ifa; i; i = i->ifa_next) {
		if (!i->ifa_addr || !i->ifa_netmask || strcmp(i->ifa_name, ifname) ||
		    (i->ifa_addr->sa_family != AF_INET && i->ifa_addr->sa_family != AF_INET6) ||
		    (i->ifa_addr->sa_family == AF_INET6 &&
		     IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)ip(i->ifa_addr))))
			continue;
		p = push(a, &n);
		if (p == NULL) {
			n = -1;
			break;
		}
		*p = (struct addr){ .family = i->ifa_addr->sa_family };
		p->len = p->family == AF_INET ? 4 : 16;
		memcpy(p->data, ip(i->ifa_addr), (size_t)p->len);
		for (j = 0; j < p->len; j++)
			p->prefix += __builtin_popcount(ip(i->ifa_netmask)[j]);
	}
	freeifaddrs(ifa);
	return n;
}

static int
add_gateway(struct addr **g, int *n, int family, struct rtattr *gw, int metric)
{
	struct addr *p;

	p = push(g, n);
	if (p == NULL)
		return -1;
	*p = (struct addr){ .family = family, .len = RTA_PAYLOAD(gw), .metric = metric };
	memcpy(p->data, RTA_DATA(gw), p->len);
	return 0;
}

int
gateways(int nlfd, int family, const char *ifname, struct addr **g)
{
	struct {
		struct nlmsghdr nh;
		struct rtmsg rtm;
	} req = {
		.nh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETROUTE,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		},
		.rtm = { .rtm_family = family },
	};
	alignas(struct nlmsghdr) char buf[8192];
	int n = 0, if_idx = 0;
	bool failed = false;
	ssize_t len;

	*g = NULL;
	if (ifname != NULL && (if_idx = if_nametoindex(ifname)) == 0) {
		warn("if_nametoindex(%s)", ifname);
		return -1;
	}

	if (send(nlfd, &req, sizeof(req), 0) < 0) {
		warn("netlink send");
		return -1;
	}
	while ((len = recv(nlfd, buf, sizeof(buf), 0)) > 0) {
		for (struct nlmsghdr *nh = (void *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			struct rtmsg *rtm = NLMSG_DATA(nh);
			int alen = RTM_PAYLOAD(nh), metric = 0, oif = 0;
			struct rtattr *gw = NULL, *mp = NULL;

			if (nh->nlmsg_type == NLMSG_DONE)
				return failed ? -1 : n;
			if (nh->nlmsg_type == NLMSG_ERROR) {
				warnx("netlink route dump failed");
				free(*g);
				*g = NULL;
				return -1;
			}
			/* Keep draining the dump after a failure. */
			if (failed)
				continue;
			if (rtm->rtm_dst_len || rtm->rtm_table != RT_TABLE_MAIN)
				continue;
			for (struct rtattr *a = RTM_RTA(rtm); RTA_OK(a, alen);
			     a = RTA_NEXT(a, alen)) {
				if (a->rta_type == RTA_OIF)
					oif = *(int *)RTA_DATA(a);
				else if (a->rta_type == RTA_PRIORITY)
					metric = *(int *)RTA_DATA(a);
				else if (a->rta_type == RTA_GATEWAY)
					gw = a;
				else if (a->rta_type == RTA_MULTIPATH)
					mp = a;
			}
			if ((if_idx == 0 || oif == if_idx) && gw &&
			    add_gateway(g, &n, rtm->rtm_family, gw, metric))
				failed = true;
			if (mp == NULL)
				continue;

			/* Multipath routes carry a gateway per next hop. */
			int mlen = RTA_PAYLOAD(mp);
			for (struct rtnexthop *rtnh = RTA_DATA(mp); RTNH_OK(rtnh, mlen);
			     mlen -= RTNH_ALIGN(rtnh->rtnh_len), rtnh = RTNH_NEXT(rtnh)) {
				int nhlen = rtnh->rtnh_len - RTNH_LENGTH(0);

				if (if_idx != 0 && rtnh->rtnh_ifindex != if_idx)
					continue;
				for (struct rtattr *a = RTNH_DATA(rtnh); RTA_OK(a, nhlen);
				     a = RTA_NEXT(a, nhlen)) {
					if (!failed && a->rta_type == RTA_GATEWAY &&
					    add_gateway(g, &n, rtm->rtm_family, a, metric))
						failed = true;
				}
			}
		}
	}
	warn("netlink receive");
	free(*g);
	*g = NULL;
	return -1;
}
