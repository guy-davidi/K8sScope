APP=exec
IMAGE=guydavidi/ebpf-exec
EBPF_DIR=ebpf/src

.PHONY: all clean run docker

all: skel
	clang $(EBPF_DIR)/exec.c -lbpf -lelf -o $(APP)

.PHONY: $(APP)
$(APP): skel
	clang $(EBPF_DIR)/exec.c -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(EBPF_DIR)/vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c $(EBPF_DIR)/exec.bpf.c -o $(EBPF_DIR)/exec.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton $(EBPF_DIR)/exec.bpf.o name exec > $(EBPF_DIR)/exec.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

# Build and push the Docker image
.PHONY: docker
docker: $(APP)
	@echo "Building Docker image..."
	docker build -t $(IMAGE) .
	@echo "Pushing Docker image to Docker Hub..."
	docker push $(IMAGE)

# New target to run your Python web application
.PHONY: web
web:
	@echo "Starting the web application..."
	python3 web/app.py

.PHONY: clean
clean:
	-rm -rf $(EBPF_DIR)/*.o $(EBPF_DIR)/*.skel.h $(EBPF_DIR)/vmlinux.h $(APP)