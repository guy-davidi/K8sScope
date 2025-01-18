#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "xdp_prog.h"
#include "xdp_prog.skel.h"

// Global variables for cleanup
static struct xdp_prog *skel = NULL;
static struct ring_buffer *ringbuf = NULL;
static struct bpf_link *link = NULL;

// Signal handler for cleanup
void handle_sigint(int sig) {
    printf("\nTerminating using signal %d ...\n", sig);

    if (ringbuf) {
        ring_buffer__free(ringbuf);
        ringbuf = NULL;
    }

    if (link) {
        bpf_link__destroy(link);
        link = NULL;
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

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    // Set up signal handler
    signal(SIGINT, handle_sigint);

    // Load and verify BPF application
    skel = xdp_prog__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Attach the XDP program to the specified interface
    link = bpf_program__attach_xdp(skel->progs.forward_non_ping, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP program to interface %s (ifindex %u)\n", argv[1], ifindex);
        xdp_prog__destroy(skel);
        return 1;
    }

    // Set up the ring buffer
    ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
    if (!ringbuf) {
        fprintf(stderr, "Failed to create ring buffer\n");
        handle_sigint(0);
    }

    printf("Successfully started! Press Ctrl+C to stop.\n");

    // Poll the ring buffer
    while (1) {
        if (ring_buffer__poll(ringbuf, 1000 /* timeout, ms */) < 0) {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    // Cleanup (if loop exits)
    handle_sigint(0);
    return 0;
}
