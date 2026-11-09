/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __SIX_EYES_MAPS_H
#define __SIX_EYES_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "headers.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct session_state);
} session_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct desync_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

#endif /* __SIX_EYES_MAPS_H */
