# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Netflix, Inc.

BINS = lacp-takeoverd lacp-watchdogd
CFLAGS += -Wall -std=gnu23 -g

all: $(BINS)

lacp-takeoverd: lacp-takeoverd.c net-common.c lacp-pdu.h lacp-watchdog.h net-common.h
	$(CC) $(CFLAGS) -o $@ lacp-takeoverd.c net-common.c $(LDFLAGS) -lpcap -lsystemd

lacp-watchdogd: lacp-watchdogd.c net-common.c lacp-watchdog.h net-common.h
	$(CC) $(CFLAGS) -o $@ lacp-watchdogd.c net-common.c $(LDFLAGS)

clean:
	rm -f $(BINS)

.PHONY: all clean
