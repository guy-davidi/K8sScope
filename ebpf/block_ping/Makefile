# ===================================
# ebpf/block_ping/Makefile
# ===================================
APP = xdp_prog

# Where to place the final user-space binary
USERSPACE_DIR ?= userspace

CLANG_FLAGS = -Wall -Wextra -g -O3 -target bpf -D__TARGET_ARCH_x86_64
LD_FLAGS    = -lbpf -lelf

all: $(USERSPACE_DIR)/$(APP)

vmlinux.h:
	@echo "[block_ping] Generating vmlinux.h"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(APP).bpf.o: vmlinux.h $(APP).bpf.c
	@echo "[block_ping] Compiling $(APP).bpf.c -> $(APP).bpf.o"
	clang $(CLANG_FLAGS) -c $(APP).bpf.c -o $(APP).bpf.o

$(APP).skel.h: $(APP).bpf.o
	@echo "[block_ping] Generating skeleton $(APP).skel.h"
	bpftool gen skeleton $(APP).bpf.o name $(APP) > $(APP).skel.h

$(USERSPACE_DIR)/$(APP): $(APP).c $(APP).skel.h
	@echo "[block_ping] Building user-space $(APP) -> $(USERSPACE_DIR)/$(APP)"
	mkdir -p $(USERSPACE_DIR)
	clang -Wall -Wextra $(APP).c -o $(USERSPACE_DIR)/$(APP) $(LD_FLAGS)

clean:
	@echo "[block_ping] Cleaning up"
	rm -f $(APP).bpf.o $(APP).skel.h vmlinux.h
	rm -f $(USERSPACE_DIR)/$(APP)
