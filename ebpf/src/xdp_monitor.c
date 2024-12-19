#include "xdp_monitor.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx) {
    bpf_printk("Packet received!");
    return XDP_PASS; // Just let the packet pass through
}

char LICENSE[] SEC("license") = "GPL";
