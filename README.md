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


List the XDP program attached to an interface:
ip link show dev eth0

Remove the XDP program from the interface:
sudo ip link set dev eth0 xdp off

Verify removal:
ip link show dev eth0

show all ebpf prgrams using:
sudo bpftool prog show

