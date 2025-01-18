#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "xdp_prog.h"
#include "xdp_prog.skel.h"

// Global variables for cleanup and detachment.
static struct xdp_prog *skel = NULL;
static struct ring_buffer *ringbuf = NULL;
static unsigned int g_ifindex = 0;
static int g_xdp_flags = 0;

// Signal handler for cleanup
void handle_sigint(int sig) {
    printf("\nTerminating using signal %d ...\n", sig);

    // Detach the XDP program if attached.
    if (g_ifindex) {
        if (bpf_xdp_detach(g_ifindex, g_xdp_flags, NULL) < 0) {
            perror("bpf_xdp_detach");
        }
        g_ifindex = 0;
    }

    if (ringbuf) {
        ring_buffer__free(ringbuf);
        ringbuf = NULL;
    }

    if (skel) {
        xdp_prog__destroy(skel);
        skel = NULL;
    }

    exit(0);
}

// Event handler for the ring buffer
int handle_event(void *ctx __attribute__((unused)), void *data, size_t len __attribute__((unused))) {
    struct packet_event *msg = (struct packet_event *)data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

    printf("--- Got ping! ---\n");
    if (inet_ntop(AF_INET, &(msg->saddr), src_ip, INET_ADDRSTRLEN)) {
        printf("Source IP: %s\n", src_ip);
    }
    if (inet_ntop(AF_INET, &(msg->daddr), dst_ip, INET_ADDRSTRLEN)) {
        printf("Destination IP: %s\n", dst_ip);
    }
    printf("Protocol: %u, ICMP Type: %u\n", msg->protocol, msg->icmp_type);
    return 0;
}

int main(int argc, char *argv[]) {
    unsigned int ifindex;
    // Default flag: allow update on an interface with no XDP program
    int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    int use_skb_mode = 0;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <interface> [--skb]\n", argv[0]);
        return 1;
    }

    if (argc == 3 && strcmp(argv[2], "--skb") == 0) {
        xdp_flags |= XDP_FLAGS_SKB_MODE;
        use_skb_mode = 1;
    } else {
        xdp_flags |= XDP_FLAGS_DRV_MODE; // Use native driver mode by default
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }
    // Save for later detachment.
    g_ifindex = ifindex;
    g_xdp_flags = xdp_flags;

    // Set up signal handler
    signal(SIGINT, handle_sigint);

    // Load and verify BPF application
    skel = xdp_prog__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Retrieve the file descriptor of the BPF program we want to attach.
    int prog_fd = bpf_program__fd(skel->progs.forward_non_ping);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program file descriptor\n");
        xdp_prog__destroy(skel);
        return 1;
    }

    // Attach the XDP program with the given flags
    int err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    if (err < 0) {
        fprintf(stderr, "Failed to attach XDP program to interface %s (ifindex %u) in %s mode: %s\n",
                argv[1], ifindex, use_skb_mode ? "SKB" : "native", strerror(-err));
        xdp_prog__destroy(skel);
        return 1;
    }

    // Set up the ring buffer for events.
    ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
    if (!ringbuf) {
        fprintf(stderr, "Failed to create ring buffer\n");
        handle_sigint(0);
    }

    printf("Successfully started in %s mode! Press Ctrl+C to stop.\n", use_skb_mode ? "SKB" : "native");

    // Poll the ring buffer.
    while (1) {
        err = ring_buffer__poll(ringbuf, 1 /* timeout, ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // Cleanup if loop exits.
    handle_sigint(0);
    return 0;
}
