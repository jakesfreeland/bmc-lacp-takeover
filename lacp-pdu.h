/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#pragma once

#include <linux/if_ether.h>
#include <stdint.h>

#define	LACP_TLV_ACTOR		1
#define	LACP_TLV_PARTNER	2
#define	LACP_STATE_DEFAULTED	0x40

struct [[gnu::packed]] lacp_info {
	uint8_t		tlv_type;
	uint8_t		tlv_len;
	uint16_t	sys_prio;
	uint8_t		sys_mac[ETH_ALEN];
	uint16_t	key;
	uint16_t	port_prio;
	uint16_t	port;
	uint8_t		state;
	uint8_t		reserved[3];
};

/* Ethernet frame carrying an IEEE 802.3ad LACPDU. */
struct [[gnu::packed]] lacp_frame {
	struct ethhdr	eth;
	uint8_t		subtype;
	uint8_t		version;
	struct lacp_info actor;
	struct lacp_info partner;
	uint8_t		collector_tlv_type;
	uint8_t		collector_tlv_len;
	uint16_t	collector_max_delay;
	uint8_t		collector_reserved[12];
	uint8_t		terminator_tlv_type;
	uint8_t		terminator_tlv_len;
	uint8_t		terminator_reserved[50];
};
