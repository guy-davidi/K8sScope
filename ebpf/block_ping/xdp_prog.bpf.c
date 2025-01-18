#include "vmlinux.h"               // Auto-generated header providing kernel definitions
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>     // Core helpers for reading kernel memory safely
#include <bpf/bpf_endian.h>        // Provides bpf_htons and other endian helpers

// Define missing constants
#define ETH_P_IP 0x0800
#define ICMP_ECHO 8

// Define the structure for sending data to userspace
struct packet_event {
    __u32 saddr;    // Source IP address
    __u32 daddr;    // Destination IP address
    __u8 protocol;  // Protocol type
    __u8 icmp_type; // ICMP type (if applicable)
};

// Create a ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB buffer
} ringbuf SEC(".maps");

SEC("xdp")
int forward_non_ping(struct xdp_md *ctx)
{
    // Data pointers
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // Not enough data, let kernel handle it

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IPv4 header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Prepare the event for the ring buffer
    struct packet_event *evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), 0);
    if (!evt)
        return XDP_PASS;

    evt->saddr = ip->saddr;
    evt->daddr = ip->daddr;
    evt->protocol = ip->protocol;
    evt->icmp_type = 0; // Default

    // Check if the packet is ICMP
    if (ip->protocol == IPPROTO_ICMP) {
        // Calculate IP header length (it can be >20 bytes due to options)
        int ip_hdr_len = ip->ihl * 4;
        struct icmphdr *icmp = data + sizeof(struct ethhdr) + ip_hdr_len;
        if ((void *)(icmp + 1) > data_end) {
            bpf_ringbuf_discard(evt, 0); // Discard event on parsing failure
            return XDP_PASS;
        }

        // Log ICMP type
        evt->icmp_type = icmp->type;

        // If it is an ICMP Echo Request (ping), drop it
        if (icmp->type == ICMP_ECHO) {
            bpf_ringbuf_submit(evt, 0); // Submit the event to userspace
            return XDP_DROP;
        }
    }

    // For non-ICMP packets, forward them
    bpf_ringbuf_submit(evt, 0); // Submit the event to userspace
    return XDP_PASS; // Keep non-forwarded packets in kernel stack
}

char _license[] SEC("license") = "GPL";
