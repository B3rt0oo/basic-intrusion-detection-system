// Minimal eBPF skeleton for IDS events via ring buffer.
// This file does not attach to any hooks; it only defines a ringbuf map and
// event struct. Attach programs should be added to push events into the ring.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event_v4 {
    __u64 ts_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u8  proto; // 6=tcp,17=udp
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

