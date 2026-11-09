/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __SIX_EYES_HEADERS_H
#define __SIX_EYES_HEADERS_H

#include <linux/types.h>

#define TCP_STATE_INIT         0
#define TCP_STATE_SYN_SENT     1
#define TCP_STATE_ESTABLISHED  2
#define TCP_STATE_SPLIT_ACTIVE 3
#define TCP_STATE_DESYNC_DONE  4

#define STAT_TOTAL_PACKETS     0
#define STAT_FAKE_RST_COUNT    1
#define STAT_SPLIT_COUNT       2
#define STAT_OVERLAP_COUNT     3
#define STAT_ERRORS            4

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct session_state {
    __u32 isn;
    __s32 seq_offset;
    __u8  state;
    __u8  strategy;
    __u8  desync_triggered;
    __u64 packets_processed;
};

struct desync_config {
    __u8  enabled;
    __u8  strategy;
    __u16 split_pos;
    __u8  fake_ttl;
    __u8  bad_checksum;
    __u16 window_scale;
};

#endif /* __SIX_EYES_HEADERS_H */
