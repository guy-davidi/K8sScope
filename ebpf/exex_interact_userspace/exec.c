#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <signal.h>
#include "exec.skel.h"
#include "exec.h"

// Global variables for cleanup
static struct exec *skel = NULL;
static struct ring_buffer *rb = NULL;

// Signal handler for cleanup
static void handle_signal(int sig)
{
    fprintf(stdout, "\nReceived signal %d, cleaning up...\n", sig);

    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }

    if (skel) {
        exec__detach(skel);
        exec__destroy(skel);
        skel = NULL;
    }

    exit(0);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static int handle_evt(void *ctx, void *data, size_t sz)
{
    const struct exec_evt *evt = data;

    fprintf(stdout, "tgid: %d <> pid: %d -- comm: %s <> file: %s\n", evt->tgid, evt->pid, evt->comm, evt->file);

    return 0;
}

int main(void)
{
    // Set up signal handlers for clean exit
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    bump_memlock_rlimit();

    // Open, load, and attach the eBPF program
    skel = exec__open();
    if (!skel) {
        fprintf(stderr, "Failed to open eBPF skeleton!\n");
        return 1;
    }

    if (exec__load(skel)) {
        fprintf(stderr, "Failed to load eBPF skeleton!\n");
        exec__destroy(skel);
        return 1;
    }

    if (exec__attach(skel)) {
        fprintf(stderr, "Failed to attach eBPF skeleton!\n");
        exec__destroy(skel);
        return 1;
    }

    // Create the ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_evt, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer!\n");
        exec__detach(skel);
        exec__destroy(skel);
        return 1;
    }

    fprintf(stdout, "Running... Press Ctrl+C to stop.\n");

    // Poll the ring buffer
    while (1) {
        ring_buffer__poll(rb, 1000);
    }

    // Cleanup (in case loop exits)
    handle_signal(0);
    return 0;
}
