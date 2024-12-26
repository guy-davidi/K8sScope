# Base image with eBPF dependencies
FROM debian:bullseye-slim

# Install necessary packages for eBPF development and running the application
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    build-essential \
    linux-headers-generic \
    iproute2 \
    linux-perf \
    bpftool \
    && apt-get clean

# Copy source files
WORKDIR /app
COPY . .

# Build eBPF and user space program
RUN make all

# Entry point for the user space program
CMD ["./exec"]
