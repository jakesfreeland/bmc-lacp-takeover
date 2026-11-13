/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Netflix, Inc.
 */

#pragma once

#include <stdint.h>

#define	DEF_WATCHDOG_ADDR	"192.168.20.1"
#define	DEF_WATCHDOG_PORT	1190
#define	DEF_WATCHDOG_TIMO_SEC	4

enum watchdog_op: uint8_t {
	RESET,				/* Reset (enable) watchdog timer. */
	SET_TIMEOUT,			/* Set new watchdog timeout. */
	DISABLE,			/* Disable watchdog timer. */
};

struct [[gnu::packed]] watchdog_msg {
	enum watchdog_op wm_op;		/* Watchdog operation. */
	uint32_t wm_len;		/* Remaining payload size. */
	uint8_t wm_data[];		/* Remaining payload. */
};

static inline const char *
wm_op_str(enum watchdog_op op) {
	switch (op) {
	case RESET:
		return "reset";
	case SET_TIMEOUT:
		return "set timeout";
	case DISABLE:
		return "disable";
	default:
		return "unknown";
	}
}

static inline bool
wm_op_len_verify(enum watchdog_op op, uint32_t len)
{
	switch (op) {
	case RESET:
	case DISABLE:
		if (len == 0)
			return true;
		break;
	case SET_TIMEOUT:
		if (len == sizeof(uint32_t))
			return true;
		break;
	}

	return false;
}
