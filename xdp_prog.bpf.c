// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>          // XDP_DROP, XDP_PASS, struct xdp_md, BPF_MAP_TYPE_* constants
#include <linux/if_ether.h>     // struct ethhdr, ETH_P_IP
#include <linux/ip.h>           // struct iphdr (IPv4 header layout)
#include <bpf/bpf_helpers.h>    // SEC(), __uint(), __type(), bpf_map_lookup_elem()
#include <bpf/bpf_endian.h>     // bpf_htons() for byte-order conversion
#include "common.h"

#include <linux/tcp.h>          // struct tcphdr
#include <linux/in.h>           // IPPROTO_TCP

/* ---------- MAP 1: allowlist (key = source IPv4, value = boolean dummy) ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips SEC(".maps");

/* ---------- MAP 2: blocklist (key = source IPv4, value = drop counter) ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);   // hash table: ~O(1) lookup
    __uint(max_entries, 10240);        // capacity is fixed at creation; the kernel preallocates
    __type(key, __u32);                // IPv4 address as 32-bit integer (network byte order)
    __type(value, struct block_record); // drop counter + expiry timestamp
} blocked_ips SEC(".maps");            // SEC(".maps") puts this into the ELF ".maps" section
// so libbpf knows to create a map from it

/* ---------- MAP 3: global counters, one slot per CPU (no lock contention) ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);            // index 0 = dropped, index 1 = passed
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* ---------- MAP 4: ring buffer for sampled drop events ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   // 256 KB buffer
} events SEC(".maps");

struct rate_state_record {
    __u64 window_start_ns;
    __u32 count;
    __u32 pad;
};

/* ---------- MAP 5: LRU hash for SYN rate limiting ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_state_record);
} rate_state SEC(".maps");

/* ---------- MAP 6: config limits ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} limits SEC(".maps");

struct scan_state_record {
    __u64 window_start_ns;
    __u32 count;           // Number of distinct ports seen in this window
    __u16 last_ports[8];   // Small array of recently seen ports (approximation)
    __u8  index;           // Circular buffer index for last_ports
    __u8  reported;        // Avoid emitting multiple events in the same window
    __u16 pad;
};

/* ---------- MAP 8: port scan state ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);    // src_ip
    __type(value, struct scan_state_record);
} scan_state SEC(".maps");

/* ---------- MAP 7: protocol counters ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);            // 0=TCP, 1=UDP, 2=ICMP, 3=Other
    __type(key, __u32);
    __type(value, __u64);
} proto_stats SEC(".maps");

/* Helper: increment stats[idx]. __always_inline because old BPF disallowed real function
 calls; the compiler must paste this body into the caller. */
 static __always_inline void bump(__u32 idx)
 {
     __u64 *counter = bpf_map_lookup_elem(&stats, &idx); // returns pointer into kernel memory, or NULL
     if (counter)        // MANDATORY NULL CHECK: the verifier rejects the program if you
         (*counter)++;   // dereference the pointer without checking it. No atomic needed:
 }                       // per-CPU slots are only touched by the CPU that owns them.
 
 static __always_inline void bump_proto(__u32 idx)
 {
     __u64 *counter = bpf_map_lookup_elem(&proto_stats, &idx);
     if (counter)
         (*counter)++;
 }

 SEC("xdp")                                  // marks this function as an XDP program
 int xdp_firewall(struct xdp_md *ctx)        // ctx holds two numbers: address of first byte
 {                                           // of the packet and address just past the last byte
     void *data     = (void *)(long)ctx->data;      // ctx->data is a 32-bit field; cast via long to
     void *data_end = (void *)(long)ctx->data_end;  // make a full pointer. Start/end of the packet.

     /* ---- Layer 2: Ethernet header (14 bytes: dst MAC 6, src MAC 6, ethertype 2) ---- */
     struct ethhdr *eth = data;                     // overlay the struct on the first 14 bytes
     if ((void *)(eth + 1) > data_end) {            // POINTER ARITHMETIC: eth + 1 advances by
         return XDP_PASS;                           // sizeof(struct ethhdr) = 14 bytes, i.e. one
     }                                              // struct past eth. If that lies beyond the end of
     // the packet, the packet is too short. VERIFIER
     // RULE: you must prove every access is in
     // bounds BEFORE you touch it; otherwise load fails.

     if (eth->h_proto != bpf_htons(ETH_P_IP)) {     // EtherType is big-endian on the wire (0x0800 = IPv4).
         return XDP_PASS;                           // Convert our constant to network order (done at
     }                                              // compile time). Not IPv4 (ARP, IPv6, VLAN)? Let it through.

     /* ---- Layer 3: IPv4 header (starts right after Ethernet) ---- */
     struct iphdr *ip = (void *)(eth + 1);          // byte 14 of the packet
     if ((void *)(ip + 1) > data_end) {             // again prove the 20-byte base IPv4 header is in bounds
         return XDP_PASS;                           // (ip + 1 advances by sizeof(struct iphdr) = 20)
     }

     __u32 src_ip = ip->saddr;                      // source address; stays in network byte order, which
     // is what user space stores as key (inet_pton output)
     
     if (ip->protocol == IPPROTO_TCP) bump_proto(0);
     else if (ip->protocol == IPPROTO_UDP) bump_proto(1);
     else if (ip->protocol == IPPROTO_ICMP) bump_proto(2);
     else bump_proto(3);

     /* ---- Check Allowlist FIRST ---- */
     __u8 *allowed = bpf_map_lookup_elem(&allowed_ips, &src_ip);
     if (allowed) {
         bump(1);
         return XDP_PASS;
     }

     /* ---- Consult the shared whiteboard ---- */
     struct block_record *rec = bpf_map_lookup_elem(&blocked_ips, &src_ip);
     if (rec) {
         if (rec->expires_at_ns == 0 || bpf_ktime_get_ns() <= rec->expires_at_ns) {
             __u64 old_hits = __sync_fetch_and_add(&rec->hits, 1);       // atomic += 1
             bump(0);                                   // global "dropped" counter
             
             // Sample drop events (every 64th packet) so a flood doesn't flood user space
             if ((old_hits % 64) == 0) {
                 struct drop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
                 if (e) { // MANDATORY NULL CHECK: verifier rejects without this
                     e->ts_ns = bpf_ktime_get_ns();
                     e->src_ip = src_ip;
                     e->reason = REASON_BLOCKLIST;
                     e->total_hits = old_hits + 1;
                     bpf_ringbuf_submit(e, 0);
                 }
             }
             return XDP_DROP;                           // verdict: discard now
         }
     }

     /* ---- Rate Limiter for TCP SYN ---- */
     if (ip->protocol == IPPROTO_TCP) {
         // Verifier check: Ensure IP header length is valid before pointer arithmetic
         if (ip->ihl < 5) return XDP_PASS;
         
         struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
         // Verifier check: Ensure TCP header is within packet bounds
         if ((void *)(tcp + 1) > data_end) {
             return XDP_PASS;
         }
         
         if (tcp->syn && !tcp->ack) {
             __u64 now = bpf_ktime_get_ns();
             
             /* ---- Port Scan Detector ---- */
             struct scan_state_record *ss = bpf_map_lookup_elem(&scan_state, &src_ip);
             __u16 dport = tcp->dest;
             __u8 new_port = 1;
             
             if (ss) {
                 if (now - ss->window_start_ns >= 5000000000ULL) { // 5 seconds
                     ss->window_start_ns = now;
                     ss->count = 1;
                     ss->index = 0;
                     ss->reported = 0;
                     __builtin_memset(ss->last_ports, 0, sizeof(ss->last_ports));
                     ss->last_ports[0] = dport;
                 } else {
                     #pragma unroll
                     for (int i = 0; i < 8; i++) {
                         if (ss->last_ports[i] == dport) {
                             new_port = 0;
                             break;
                         }
                     }
                     if (new_port) {
                         ss->count++;
                         ss->index = (ss->index + 1) & 7; // mod 8
                         ss->last_ports[ss->index] = dport;
                     }
                     if (ss->count >= 10 && !ss->reported) {
                         ss->reported = 1;
                         struct drop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
                         if (e) {
                             e->ts_ns = now;
                             e->src_ip = src_ip;
                             e->reason = REASON_PORTSCAN;
                             e->total_hits = ss->count;
                             bpf_ringbuf_submit(e, 0);
                         }
                     }
                 }
             } else {
                 struct scan_state_record new_ss = {};
                 new_ss.window_start_ns = now;
                 new_ss.count = 1;
                 new_ss.last_ports[0] = dport;
                 bpf_map_update_elem(&scan_state, &src_ip, &new_ss, BPF_ANY);
             }
             struct rate_state_record *rs = bpf_map_lookup_elem(&rate_state, &src_ip);
             __u32 current_count = 1;
             
             if (rs) {
                 if (now - rs->window_start_ns >= 1000000000ULL) { // 1 second
                     rs->window_start_ns = now;
                     rs->count = 1;
                 } else {
                     rs->count++;
                     current_count = rs->count;
                 }
             } else {
                 struct rate_state_record new_rs = {};
                 new_rs.window_start_ns = now;
                 new_rs.count = 1;
                 bpf_map_update_elem(&rate_state, &src_ip, &new_rs, BPF_ANY);
             }
             
             __u32 zero = 0;
             __u32 *thresh = bpf_map_lookup_elem(&limits, &zero);
             __u32 limit_val = thresh ? *thresh : 200;
             
             if (current_count > limit_val) {
                 bump(0);
                 if ((current_count % 64) == 0) {
                     struct drop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
                     if (e) {
                         e->ts_ns = now;
                         e->src_ip = src_ip;
                         e->reason = REASON_RATELIMIT;
                         e->total_hits = current_count;
                         bpf_ringbuf_submit(e, 0);
                     }
                 }
                 return XDP_DROP;
             }
         }
     }

     bump(1);                                       // global "passed" counter
     return XDP_PASS;                               // verdict: continue into the normal network stack
 }

 char LICENSE[] SEC("license") = "GPL";             // Some helpers are GPL-only. The kernel checks this
 // string; without it many programs won't load.
