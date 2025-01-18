APP = xdp_prog

BPF_PROG = $(APP).bpf.c
BPF_OBJ = $(APP).bpf.o
BPF_SKEL = $(APP).skel.h
BPF_VMLINUX = vmlinux.h
EBPF_DIR = $(shell pwd)
USER_SPACE_DIR = $(shell pwd)

CLANG_FLAGS = -Wall -Wextra -g -O3 -target bpf -D__TARGET_ARCH_x86_64
GCC_FLAGS = -Wall -Wextra -lbpf -lelf

.PHONY: all clean skel run

# Create virtual environment and install Flask if not already set up
$(VENV)/bin/activate:
	@echo "Setting up virtual environment..."
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install flask

all: $(USER_SPACE_DIR)/$(APP)

$(USER_SPACE_DIR)/$(APP): skel
	@echo "Building the executable..."
	clang -Wall -Wextra $(EBPF_DIR)/$(APP).c -o $(USER_SPACE_DIR)/$(APP) -lbpf -lelf

.PHONY: vmlinux
vmlinux: mount_bpf
	@echo "Generating vmlinux.h..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(EBPF_DIR)/vmlinux.h

.PHONY: bpf
bpf: vmlinux
	@echo "Compiling eBPF program..."
	clang -Wall -Wextra -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c $(EBPF_DIR)/$(APP).bpf.c -o $(EBPF_DIR)/$(APP).bpf.o

.PHONY: skel
skel: bpf
	@echo "Generating eBPF skeleton..."
	bpftool gen skeleton $(EBPF_DIR)/$(APP).bpf.o name $(APP) > $(EBPF_DIR)/$(APP).skel.h

.PHONY: mount_debugfs
mount_debugfs:
	@echo "Checking if debugfs is mounted..."
	@if ! mountpoint -q /sys/kernel/debug; then \
		echo "Mounting debugfs..."; \
		sudo mount -t debugfs none /sys/kernel/debug; \
	fi

.PHONY: mount_bpf
mount_bpf:
	@echo "Checking if BPF filesystem is mounted..."
	@if ! mountpoint -q /sys/fs/bpf; then \
		echo "Mounting BPF filesystem..."; \
		sudo mount -t bpf bpf /sys/fs/bpf; \
	fi

.PHONY: run
run: $(USER_SPACE_DIR)/$(APP)
	@echo "Running the executable..."
	sudo $(USER_SPACE_DIR)/$(APP) eth0

.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(USER_SPACE_DIR)/$(APP)
	rm -f $(EBPF_DIR)/$(APP).bpf.o
	rm -f $(EBPF_DIR)/$(APP).skel.h
	rm -f vmlinux.h