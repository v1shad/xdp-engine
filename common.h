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

#endif
