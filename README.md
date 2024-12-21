# eBPF && KinD Kubernetes Monitoring Example

## Overview
This minimal project creates a local Kubernetes cluster with KinD, compiles a simple eBPF program, and demonstrates how to manually load the eBPF program to monitor traffic. A BusyBox pod is deployed to generate some network traffic. The eBPF program simply prints a message whenever it sees a packet.

## Prerequisites
- [KinD](https://kind.sigs.k8s.io/)
- `clang`, `llvm`, `bpftool` installed
- `kubectl` installed

## Steps

1. **Create the KinD Cluster:**
   ```bash
   cd kind-cluster
   ./create-cluster.sh



## Remove the XDP program from the interface:
```
sudo ip link set dev eth0 xdp off
```

## Verify removal:
```
ip link show dev eth0
```

## show all ebpf prgrams using:
```
sudo bpftool prog show
```

## Load the program into the kernel:
```
sudo bpftool prog load xdp_prog.o /sys/fs/bpf/guy_xdp_prog
```

## Attach the program to the desired interface:
```
sudo bpftool net attach xdp pinned /sys/fs/bpf/guy_xdp_prog dev eth0

```

## List the XDP program attached to an interface:
```
ip link show dev eth0
```

## Verify the Program is Attached
```
sudo bpftool net show

```

## To trace our ebpf program
```
cat /sys/kernel/tracing/trace_pipe 
```

## Documentation to get system call forma
here we can see the file name in offset 16 -> 16*8(bits)=128->2*64bits
```

└─# cat sys_enter_execve/format  
name: sys_enter_execve
ID: 810
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * filename;	offset:16;	size:8;	signed:0;
	field:const char *const * argv;	offset:24;	size:8;	signed:0;
	field:const char *const * envp;	offset:32;	size:8;	signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
```
