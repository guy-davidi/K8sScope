# Makefile to compile XDP eBPF program

# Define the BPF target
CLANG = clang
BPF_FLAGS = -O2 -target bpf
OBJ_FILE = xdp_prog.o
SRC_FILE = xdp_prog.c

# Additional include paths
INCLUDE_PATH = /usr/lib/linux/uapi/x86
KERNEL_HEADERS = /usr/src/linux-headers-$(shell uname -r)/include
SYSTEM_HEADERS = /usr/include/x86_64-linux-gnu

# Compiler options
CFLAGS = -Wall -g -I$(INCLUDE_PATH) -I$(KERNEL_HEADERS) -I$(SYSTEM_HEADERS) -m64

# Default target
all: $(OBJ_FILE)

# Rule to compile the source file into the object file
$(OBJ_FILE): $(SRC_FILE)
	$(CLANG) $(BPF_FLAGS) $(CFLAGS) -c $(SRC_FILE) -o $(OBJ_FILE)

# Rule to clean up object files
clean:
	rm -f $(OBJ_FILE)

# Phony targets
.PHONY: all clean
