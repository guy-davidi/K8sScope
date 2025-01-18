APP=exec
IMAGE=guydavidi/ebpf-exec
EBPF_DIR=ebpf/src
VENV=venv
USER_SPACE_DIR=userspace

.PHONY: all clean run docker web venv mount_debugfs mount_bpf

# Create virtual environment and install Flask if not already set up
$(VENV)/bin/activate:
	@echo "Setting up virtual environment..."
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install flask

all: $(APP)

$(USER_SPACE_DIR)/$(APP): skel
	@echo "Building the executable..."
	clang -Wall -Wextra $(EBPF_DIR)/exec.c -o $(USER_SPACE_DIR)/$(APP) -lbpf -lelf

.PHONY: vmlinux
vmlinux: mount_bpf
	@echo "Generating vmlinux.h..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(EBPF_DIR)/vmlinux.h

.PHONY: bpf
bpf: vmlinux
	@echo "Compiling eBPF program..."
	clang -Wall -Wextra -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c $(EBPF_DIR)/exec.bpf.c -o $(EBPF_DIR)/exec.bpf.o

.PHONY: skel
skel: bpf
	@echo "Generating eBPF skeleton..."
	bpftool gen skeleton $(EBPF_DIR)/exec.bpf.o name exec > $(EBPF_DIR)/exec.skel.h

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
run: mount_debugfs mount_bpf $(APP)
	@echo "Running the application..."
	sudo ./$(USER_SPACE_DIR)/$(APP)

# Build and push the Docker image
.PHONY: docker
docker: $(USER_SPACE_DIR)/$(APP)
	@echo "Building Docker image..."
	docker build -t $(IMAGE) .
	@echo "Pushing Docker image to Docker Hub..."
	docker push $(IMAGE)

# Run the web application inside the virtual environment
.PHONY: web
web: $(VENV)/bin/activate bpf mount_debugfs mount_bpf $(USER_SPACE_DIR)/$(APP)
	@echo "Starting the web application..."
	$(VENV)/bin/python3 web/backend/app.py

.PHONY: clean
clean:
	@echo "Cleaning up generated files..."
	rm -rf $(EBPF_DIR)/*.o $(EBPF_DIR)/*.skel.h $(EBPF_DIR)/vmlinux.h $(USER_SPACE_DIR)/$(APP)
	@echo "Removing virtual environment..."
	rm -rf $(VENV)
	@echo "Docker image cleanup: use 'docker image rm $(IMAGE)' if needed."

.PHONY: 
unmount:
	@echo "Unmounting debugfs and BPF filesystem if mounted..."
	@if mountpoint -q /sys/kernel/debug; then \
		echo "Unmounting debugfs..."; \
		sudo umount /sys/kernel/debug; \
	fi
	@if mountpoint -q /sys/fs/bpf; then \
		echo "Unmounting BPF filesystem..."; \
		sudo umount /sys/fs/bpf; \
	fi

.PHONY: clean-all
clean-all: clean unmount
	@echo "Removing virtual environment..."
	rm -rf $(VENV)