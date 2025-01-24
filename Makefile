# =====================================
# Root Makefile for the entire project
# =====================================

TOPDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Where we want user-space binaries placed
USERSPACE_DIR := $(TOPDIR)/userspace

# Virtual environment for Python/Flask
VENV := $(TOPDIR)/venv

# Subdirectories under "ebpf/" that contain eBPF programs
EBPF_SUBDIRS = \
    ebpf/exec_syscall \
    ebpf/block_ping

APP := exec                # Example main eBPF user-space app if you have one
IMAGE := guydavidi/ebpf-exec

.PHONY: all subdirs web run docker clean clean-all \
        mount_debugfs mount_bpf unmount venv

##--------------------------------------
## "all" builds everything
##--------------------------------------
all: subdirs

##--------------------------------------
## Build all eBPF subdirs
##--------------------------------------
subdirs:
	@echo "[Root] Building all eBPF subdirectories..."
	@for dir in $(EBPF_SUBDIRS); do \
	  echo ">>> Entering $$dir"; \
	  $(MAKE) -C $$dir USERSPACE_DIR=$(USERSPACE_DIR); \
	  echo "<<< Leaving  $$dir"; \
	done

##--------------------------------------
## Virtual environment for Flask
##--------------------------------------
$(VENV)/bin/activate:
	@echo "[Root] Setting up virtual environment in $(VENV)..."
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install flask

##--------------------------------------
## 'web' target: mount BPF, build everything, then run Flask
##--------------------------------------
web: $(VENV)/bin/activate all mount_debugfs mount_bpf
	@echo "[Root] Starting Flask web app..."
	$(VENV)/bin/python3 web/backend/app.py

##--------------------------------------
## Example 'run' target: run your main eBPF user-space app
##--------------------------------------
run: all mount_debugfs mount_bpf
	@echo "[Root] Running the main eBPF user-space app: $(APP)"
	sudo $(USERSPACE_DIR)/$(APP)

##--------------------------------------
## Docker
##--------------------------------------
docker: all
	@echo "[Root] Building Docker image..."
	docker build -t $(IMAGE) .
	@echo "[Root] Pushing Docker image..."
	docker push $(IMAGE)

##--------------------------------------
## Mount debugfs, BPF filesystem
##--------------------------------------
mount_debugfs:
	@echo "[Root] Checking if debugfs is mounted..."
	@if ! mountpoint -q /sys/kernel/debug; then \
		echo "[Root] Mounting debugfs..."; \
		sudo mount -t debugfs none /sys/kernel/debug; \
	fi

mount_bpf:
	@echo "[Root] Checking if BPF filesystem is mounted..."
	@if ! mountpoint -q /sys/fs/bpf; then \
		echo "[Root] Mounting BPF filesystem..."; \
		sudo mount -t bpf bpf /sys/fs/bpf; \
	fi

unmount:
	@echo "[Root] Unmounting debugfs and BPF if mounted..."
	@if mountpoint -q /sys/kernel/debug; then \
		echo "Unmounting debugfs..."; \
		sudo umount /sys/kernel/debug; \
	fi
	@if mountpoint -q /sys/fs/bpf; then \
		echo "Unmounting /sys/fs/bpf..."; \
		sudo umount /sys/fs/bpf; \
	fi

##--------------------------------------
## Clean
##--------------------------------------
clean:
	@echo "[Root] Cleaning subdirectories..."
	@for dir in $(EBPF_SUBDIRS); do \
	  echo ">>> Cleaning in $$dir"; \
	  $(MAKE) -C $$dir clean USERSPACE_DIR=$(USERSPACE_DIR); \
	done
	@echo "[Root] Removing files in userspace/..."
	rm -f $(USERSPACE_DIR)/*
	@echo "[Root] Done cleaning. (userspace is empty now)"

clean-all: clean unmount
	@echo "[Root] Removing virtual environment..."
	rm -rf $(VENV)
	@echo "[Root] Done clean-all."
