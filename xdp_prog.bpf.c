// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>          // XDP_DROP, XDP_PASS, struct xdp_md, BPF_MAP_TYPE_* constants
#include <linux/if_ether.h>     // struct ethhdr, ETH_P_IP
#include <linux/ip.h>           // struct iphdr (IPv4 header layout)
#include <bpf/bpf_helpers.h>    // SEC(), __uint(), __type(), bpf_map_lookup_elem()
#include <bpf/bpf_endian.h>     // bpf_htons() for byte-order conversion
#include "common.h"

/* ---------- MAP 1: blocklist (key = source IPv4, value = drop counter) ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);   // hash table: ~O(1) lookup
    __uint(max_entries, 10240);        // capacity is fixed at creation; the kernel preallocates
    __type(key, __u32);                // IPv4 address as 32-bit integer (network byte order)
    __type(value, struct block_record); // drop counter + expiry timestamp
} blocked_ips SEC(".maps");            // SEC(".maps") puts this into the ELF ".maps" section
// so libbpf knows to create a map from it

/* ---------- MAP 2: global counters, one slot per CPU (no lock contention) ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);            // index 0 = dropped, index 1 = passed
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* Helper: increment stats[idx]. __always_inline because old BPF disallowed real function
 calls; the compiler must paste this body into the caller. */
 static __always_inline void bump(__u32 idx)
 {
     __u64 *counter = bpf_map_lookup_elem(&stats, &idx); // returns pointer into kernel memory, or NULL
     if (counter)        // MANDATORY NULL CHECK: the verifier rejects the program if you
         (*counter)++;   // dereference the pointer without checking it. No atomic needed:
 }                       // per-CPU slots are only touched by the CPU that owns them.

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

     /* ---- Consult the shared whiteboard ---- */
     struct block_record *rec = bpf_map_lookup_elem(&blocked_ips, &src_ip);
     if (rec) {
         if (rec->expires_at_ns == 0 || bpf_ktime_get_ns() <= rec->expires_at_ns) {
             __sync_fetch_and_add(&rec->hits, 1);       // atomic += 1
             bump(0);                                   // global "dropped" counter
             return XDP_DROP;                           // verdict: discard now
         }
     }

     bump(1);                                       // global "passed" counter
     return XDP_PASS;                               // verdict: continue into the normal network stack
 }

 char LICENSE[] SEC("license") = "GPL";             // Some helpers are GPL-only. The kernel checks this
 // string; without it many programs won't load.
