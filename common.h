#ifndef COMMON_H
#define COMMON_H

/* 
 * Shared header between kernel (eBPF) and user space (C++).
 * Use standard fixed-width types compatible with both.
 */
struct block_record {
    __u64 hits;
    __u64 expires_at_ns; // 0 means permanent block
};

/* Event sent from XDP to user space when a packet is dropped */
struct drop_event {
    __u64 ts_ns;      // Timestamp of the drop
    __u32 src_ip;     // IP address that was dropped
    __u32 reason;     // Reason for drop (e.g., REASON_BLOCKLIST)
    __u64 total_hits; // Total times this IP has been dropped (or rate-limit count)
};

#define REASON_BLOCKLIST 0
#define REASON_RATELIMIT 1

#endif
