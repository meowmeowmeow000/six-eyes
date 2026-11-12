//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CFG_IDX_EXPECTED_TTL  0
#define CFG_IDX_TTL_TOLERANCE 1
#define CFG_IDX_LOCKDOWN_MODE 2

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, __u8);
} server_ttl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} rst_drop_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} xdp_config_map SEC(".maps");

static __always_inline __u32 get_cfg(__u32 idx, __u32 default_val) {
    __u32 *val = bpf_map_lookup_elem(&xdp_config_map, &idx);
    if (!val || *val == 0)
        return default_val;
    return *val;
}

static __always_inline int is_ttl_anomalous(__u8 packet_ttl, __u8 expected_ttl, __u32 tolerance) {
    int diff = (int)packet_ttl - (int)expected_ttl;
    int tol = (int)tolerance;
    return (diff < -tol || diff > tol);
}

static __always_inline void record_dpi_drop(void) {
    __u32 idx = 0;
    __u64 *cnt = bpf_map_lookup_elem(&rst_drop_counter, &idx);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    }
}

SEC("xdp")
int filter_dpi_rst(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    if (ip->frag_off & bpf_htons(0x1FFF))
        return XDP_PASS;
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > 60)
        return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    struct flow_key key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };
    if (tcp->syn && tcp->ack) {
        __u8 ttl = ip->ttl;
        bpf_map_update_elem(&server_ttl_map, &key, &ttl, BPF_ANY);
        return XDP_PASS;
    }
    if (tcp->rst || tcp->fin) {
        // v10 Heuristic 1: Drop non-RFC TCP RST packets carrying a payload
        // (DPI injectors frequently attach HTTP block pages or markers to RSTs)
        __u32 tcp_hdr_len = tcp->doff * 4;
        __u32 total_ip_len = bpf_ntohs(ip->tot_len);
        if (tcp->rst && total_ip_len > (ip_hdr_len + tcp_hdr_len)) {
            record_dpi_drop();
            return XDP_DROP;
        }

        __u32 tolerance = get_cfg(CFG_IDX_TTL_TOLERANCE, 4);
        __u8 *flow_ttl  = bpf_map_lookup_elem(&server_ttl_map, &key);
        if (flow_ttl) {
            if (is_ttl_anomalous(ip->ttl, *flow_ttl, tolerance)) {
                record_dpi_drop();
                return XDP_DROP;
            }
            if (tcp->rst) {
                bpf_map_delete_elem(&server_ttl_map, &key);
            }
            return XDP_PASS;
        }
        __u32 baseline_ttl = get_cfg(CFG_IDX_EXPECTED_TTL, 0);
        __u32 lockdown     = get_cfg(CFG_IDX_LOCKDOWN_MODE, 0);
        if (baseline_ttl > 0 && lockdown == 1 && bpf_ntohs(tcp->source) == 443) {
            if (is_ttl_anomalous(ip->ttl, (__u8)baseline_ttl, tolerance)) {
                record_dpi_drop();
                return XDP_DROP;
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
