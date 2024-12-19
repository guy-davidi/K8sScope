SRC_DIR = src
INC_DIR = h
OUT_DIR = build

SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(SRC_FILES:$(SRC_DIR)/%.c=$(OUT_DIR)/%.o)

CC = clang
CFLAGS = -O2 -target bpf -I$(INC_DIR)

OUTPUT = xdp_monitor.o

all: $(OUT_DIR) $(OUTPUT)

$(OUT_DIR):
	mkdir -p $@

$(OUT_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# For eBPF, $(OBJ_FILES) are already the final objects, no linking needed.
$(OUTPUT): $(OBJ_FILES)
	cp $(OBJ_FILES) $(OUTPUT)

clean:
	rm -rf $(OUT_DIR) $(OUTPUT)
