#include "vmlinux.h"               // Auto-generated header providing kernel definitions
#include <bpf/bpf_helpers.h>       // Helper functions for eBPF programs
#include <bpf/bpf_core_read.h>     // Core helpers for reading kernel memory safely
#include "exec.h"                  // Custom header file, assumed to define struct exec_evt

// Define a ring buffer map named 'rb' to store events. The ring buffer is used
// for user-space communication.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);      // Map type: Ring buffer
    __uint(max_entries, 256 * 1024);        // Maximum size: 256 KB
} rb SEC(".maps");

// Struct definition for the parameters passed to the execve syscall tracepoint.
// This is provided by the kernel tracepoint API.
struct exec_params_t {
    u64 __unused;       // Placeholder for unused fields
    u32 __unused2;      // Placeholder for unused fields
    char *file;         // Pointer to the filename being executed
};

// Define the eBPF program to attach to the tracepoint `sys_enter_execve`.
// This triggers whenever a process calls the `execve` syscall.
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct exec_params_t *params)
{
    // Get the current task (process context) using a BPF helper.
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    
    // Declare a pointer for the event structure to store data.
    struct exec_evt *evt = {0};
    
    // Reserve space in the ring buffer for the event structure.
    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    
    // If the ring buffer reservation fails, log a message and exit the program.
    if (!evt) {
        bpf_printk("ringbuffer not reserved\n");
        return 0; // Return without doing anything
    }

    // Populate the event structure with data from the current process.
    evt->tgid = BPF_CORE_READ(task, tgid); // Read thread group ID (process ID)
    evt->pid = BPF_CORE_READ(task, pid);  // Read the process ID
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm)); // Get the process name
    bpf_probe_read_user_str(evt->file, sizeof(evt->file), params->file); // Read the filename being executed

    // Submit the event to the ring buffer for user-space consumption.
    bpf_ringbuf_submit(evt, 0);

    // Log a debug message indicating that an execve syscall was handled.
    bpf_printk("Exec Called\n");

    return 0; // Indicate successful execution of the eBPF program
}

// Guy the King
char LICENSE[] SEC("license") = "GPL";
