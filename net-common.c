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
#include <string.h>

#include "net-common.h"

struct req {
	struct nlmsghdr nh;
	union {
		struct ifinfomsg ifi;
		struct ifaddrmsg ifa;
		struct rtmsg rtm;
	};
	char attrs[256];
};

static void
attr(struct req *r, int type, const void *data, int len)
{
	struct nlmsghdr *nh = &r->nh;
	struct rtattr *rta = (void *)r + NLMSG_ALIGN(nh->nlmsg_len);

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int
request(int nlfd, struct nlmsghdr *nh)
{
	struct nlmsghdr reply[64];
	struct nlmsgerr *err;
	ssize_t len;

	nh->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
	if (send(nlfd, nh, nh->nlmsg_len, 0) < 0) {
		warn("netlink send");
		return -1;
	}
	len = recv(nlfd, reply, sizeof(reply), 0);
	if (len < 0) {
		warn("netlink receive");
		return -1;
	}
	if ((size_t)len < sizeof(*reply) || reply->nlmsg_len > (size_t)len ||
	    reply->nlmsg_len < NLMSG_LENGTH(sizeof(*err)) || reply->nlmsg_type != NLMSG_ERROR) {
		warnx("invalid netlink acknowledgement for request %d", nh->nlmsg_type);
		return -1;
	}
	err = NLMSG_DATA(reply);
	if (err->error) {
		warnx("netlink %d: %s", nh->nlmsg_type, strerror(-err->error));
		return -1;
	}
	return 0;
}

static unsigned char *
ip(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return (void *)&((struct sockaddr_in *)sa)->sin_addr;
	return (void *)&((struct sockaddr_in6 *)sa)->sin6_addr;
}

int
addrs(const char *ifname, struct addr *a, int max)
{
	struct ifaddrs *ifa, *i;
	int n = 0, j;

	if (getifaddrs(&ifa)) {
		warn("getifaddrs");
		return -1;
	}
	for (i = ifa; i && n < max; i = i->ifa_next) {
		if (!i->ifa_addr || !i->ifa_netmask || strcmp(i->ifa_name, ifname) ||
		    (i->ifa_addr->sa_family != AF_INET && i->ifa_addr->sa_family != AF_INET6) ||
		    (i->ifa_addr->sa_family == AF_INET6 &&
		     IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)ip(i->ifa_addr))))
			continue;
		a[n].family = i->ifa_addr->sa_family;
		a[n].len = a[n].family == AF_INET ? 4 : 16;
		memcpy(a[n].data, ip(i->ifa_addr), (size_t)a[n].len);
		a[n].prefix = 0;
		for (j = 0; j < a[n].len; j++)
			a[n].prefix += __builtin_popcount(ip(i->ifa_netmask)[j]);
		n++;
	}
	freeifaddrs(ifa);
	return n;
}

int
set_link(int nlfd, int idx, unsigned int up)
{
	struct req r = {
		.nh = { .nlmsg_len = NLMSG_LENGTH(sizeof(r.ifi)), .nlmsg_type = RTM_NEWLINK },
		.ifi = { .ifi_index = idx, .ifi_flags = up, .ifi_change = IFF_UP },
	};

	return request(nlfd, &r.nh);
}

int
set_link_attr(int nlfd, int idx, int type, const void *data, int len)
{
	struct req r = {
		.nh = { .nlmsg_len = NLMSG_LENGTH(sizeof(r.ifi)), .nlmsg_type = RTM_NEWLINK },
		.ifi = { .ifi_index = idx },
	};

	attr(&r, type, data, len);
	return request(nlfd, &r.nh);
}

int
set_addrs(int nlfd, int type, int idx, struct addr *a, int n)
{
	for (int i = 0; i < n; i++) {
		struct req r = {
			.nh = {
				.nlmsg_len = NLMSG_LENGTH(sizeof(r.ifa)),
				.nlmsg_type = type,
				.nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE,
			},
			.ifa = { .ifa_family = a[i].family, .ifa_prefixlen = a[i].prefix,
				 .ifa_index = idx },
		};

		attr(&r, IFA_LOCAL, a[i].data, a[i].len);
		attr(&r, IFA_ADDRESS, a[i].data, a[i].len);
		if (request(nlfd, &r.nh))
			return -1;
	}
	return 0;
}

int
add_routes(int nlfd, int idx, struct addr *g, int n)
{
	for (int i = 0; i < n; i++) {
		struct req r = {
			.nh = {
				.nlmsg_len = NLMSG_LENGTH(sizeof(r.rtm)),
				.nlmsg_type = RTM_NEWROUTE,
				.nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE,
			},
			.rtm = { .rtm_family = g[i].family, .rtm_table = RT_TABLE_MAIN,
				 .rtm_protocol = RTPROT_BOOT, .rtm_type = RTN_UNICAST },
		};

		attr(&r, RTA_GATEWAY, g[i].data, g[i].len);
		attr(&r, RTA_OIF, &idx, sizeof(idx));
		if (request(nlfd, &r.nh))
			return -1;
	}
	return 0;
}

int
gateways(int nlfd, int family, int if_idx, struct addr *g, int max)
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
	int n = 0;
	ssize_t len;

	if (send(nlfd, &req, sizeof(req), 0) < 0) {
		warn("netlink send");
		return -1;
	}
	while ((len = recv(nlfd, buf, sizeof(buf), 0)) > 0) {
		for (struct nlmsghdr *nh = (void *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			struct rtmsg *rtm = NLMSG_DATA(nh);
			int alen = RTM_PAYLOAD(nh), oif = 0;
			struct rtattr *gw = NULL;

			if (nh->nlmsg_type == NLMSG_DONE)
				return n;
			if (nh->nlmsg_type == NLMSG_ERROR) {
				warnx("netlink route dump failed");
				return -1;
			}
			if (rtm->rtm_dst_len || rtm->rtm_table != RT_TABLE_MAIN)
				continue;
			for (struct rtattr *a = RTM_RTA(rtm); RTA_OK(a, alen);
			     a = RTA_NEXT(a, alen)) {
				if (a->rta_type == RTA_OIF)
					oif = *(int *)RTA_DATA(a);
				else if (a->rta_type == RTA_GATEWAY)
					gw = a;
			}
			if ((if_idx == 0 || oif == if_idx) && gw && n < max) {
				g[n] = (struct addr){ .family = rtm->rtm_family,
						      .len = RTA_PAYLOAD(gw) };
				memcpy(g[n].data, RTA_DATA(gw), g[n].len);
				n++;
			}
		}
	}
	warn("netlink receive");
	return -1;
}
