// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * SIX EYES - Autonomous eBPF TCP Sequence Desynchronization Daemon (v10)
 * Kernel-Level Packet Dissection & Atomic Sequence Manipulation
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"
#include "headers.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define STRAT_NONE           0
#define STRAT_FAKE_RST       1
#define STRAT_HTTP_SPLIT     2
#define STRAT_TLS_SPLIT      3
#define STRAT_SEQ_OVERLAP    4

SEC("classifier/egress")
int handle_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcph = (void *)((char *)iph + (iph->ihl * 4));
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    // Filter target ports: HTTP (80) & HTTPS (443)
    __u16 dport = bpf_ntohs(tcph->dest);
    if (dport != 80 && dport != 443)
        return TC_ACT_OK;

    struct flow_key key = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .sport = tcph->source,
        .dport = tcph->dest,
    };

    struct session_state *state = bpf_map_lookup_elem(&session_map, &key);
    if (!state) {
        // Track 3-way handshake on SYN packet
        if (tcph->syn && !tcph->ack) {
            struct session_state new_state = {
                .isn = bpf_ntohl(tcph->seq),
                .seq_offset = 0,
                .state = TCP_STATE_SYN_SENT,
                .strategy = STRAT_FAKE_RST,
                .packets_processed = 1,
            };
            bpf_map_update_elem(&session_map, &key, &new_state, BPF_ANY);
        }
        return TC_ACT_OK;
    }

    state->packets_processed++;

    __u16 ip_total_len = bpf_ntohs(iph->tot_len);
    __u16 tcp_hdr_len = tcph->doff * 4;
    __u16 ip_hdr_len = iph->ihl * 4;
    __s32 payload_len = ip_total_len - (ip_hdr_len + tcp_hdr_len);

    if (payload_len <= 0)
        return TC_ACT_OK;

    // Six Eyes sequence desynchronization state execution
    switch (state->strategy) {
    case STRAT_FAKE_RST: {
        __u32 stat_key = STAT_FAKE_RST_COUNT;
        __u64 *val = bpf_map_lookup_elem(&stats_map, &stat_key);
        if (val)
            __sync_fetch_and_add(val, 1);

        state->desync_triggered = 1;
        break;
    }

    case STRAT_HTTP_SPLIT:
    case STRAT_TLS_SPLIT: {
        __u32 stat_key = STAT_SPLIT_COUNT;
        __u64 *val = bpf_map_lookup_elem(&stats_map, &stat_key);
        if (val)
            __sync_fetch_and_add(val, 1);

        // Sequence number offset manipulation
        state->seq_offset += 2;
        break;
    }

    default:
        break;
    }

    bpf_map_update_elem(&session_map, &key, state, BPF_EXIST);
    return TC_ACT_OK;
}

SEC("classifier/ingress")
int handle_ingress(struct __sk_buff *skb) {
    // Ingress handler for ACK realignment
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
