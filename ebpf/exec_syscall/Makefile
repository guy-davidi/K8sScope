# ===================================
# ebpf/src/Makefile
# ===================================
# Build the "exec" eBPF program + user space

APP = exec

# If not passed in, default to a local "userspace" folder
USERSPACE_DIR ?= userspace

# clang and bpf flags
CLANG_FLAGS = -Wall -Wextra -g -O3 -target bpf -D__TARGET_ARCH_x86_64
LD_FLAGS    = -lbpf -lelf

# The final user-space binary to generate
all: $(USERSPACE_DIR)/$(APP)

# 1) Generate vmlinux.h
vmlinux.h:
	@echo "[src] Generating vmlinux.h"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2) Compile the eBPF code into an object
exec.bpf.o: vmlinux.h exec.bpf.c
	@echo "[src] Compiling eBPF program exec.bpf.c -> exec.bpf.o"
	clang $(CLANG_FLAGS) -c exec.bpf.c -o exec.bpf.o

# 3) Generate the skeleton
exec.skel.h: exec.bpf.o
	@echo "[src] Generating skeleton from exec.bpf.o -> exec.skel.h"
	bpftool gen skeleton exec.bpf.o name exec > exec.skel.h

# 4) Build user-space binary
$(USERSPACE_DIR)/$(APP): exec.c exec.skel.h
	@echo "[src] Building user-space $(APP) -> $(USERSPACE_DIR)/$(APP)"
	mkdir -p $(USERSPACE_DIR)
	clang -Wall -Wextra exec.c -o $(USERSPACE_DIR)/$(APP) $(LD_FLAGS)

clean:
	@echo "[src] Cleaning up"
	rm -f exec.bpf.o exec.skel.h vmlinux.h
	rm -f $(USERSPACE_DIR)/$(APP)
