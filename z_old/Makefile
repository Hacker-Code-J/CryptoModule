###############################################################################
# Makefile for a CryptoModule
#
# Targets:
#   build   : Compile + link everything into an executable
#   run     : Run the resulting binary
#   clean   : Remove all build artifacts
#   rebuild : Clean first, then build
# 	valgrind: Run the binary under Valgrind for memory checking
#   asan    : Build with AddressSanitizer enabled and run
#   gdb     : Build with debugging symbols and launch GDB for in-depth inspection
#   inspect : Inspect the binary with nm and objdump
# 	TBA
###############################################################################

# --- Project-wide settings ---
CC          := gcc
CFLAGS 		:= -std=c99 -g -O2 -Wall -Wextra -I. -Iinclude -Isrc

# Name of the final executable
TARGET      := cryptomodule-demo

# Directory for object files and for final binary
OBJ_DIR     := build
BIN_DIR     := bin

# Automatically find all .c files in src (including subdirectories)
SRCS := $(shell find src -name '*.c')

# Generate a list of object files by converting:
# src/xxx.c  --->  build/xxx.o (preserving the subdirectory structure relative to src)
OBJS := $(patsubst src/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# --- Phony targets (not actual files) ---
.PHONY: build run clean rebuild all

# 'all' can default to 'build'
all: build

###############################################################################
# 1) build : compile + link
###############################################################################
build: $(BIN_DIR)/$(TARGET)

# Link step: gather all objects into a single executable
$(BIN_DIR)/$(TARGET): $(OBJS)
	@echo "[LINK] Linking objects to create $@"
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

# Compile step: For each .c -> .o
$(OBJ_DIR)/%.o: src/%.c
	@echo "[CC] Compiling $< into $@"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

###############################################################################
# 2) run : run the resulting binary
###############################################################################
run: build
	@echo "[RUN] Running $(BIN_DIR)/$(TARGET)"
	@./$(BIN_DIR)/$(TARGET)

###############################################################################
# 3) clean : remove build artifacts
###############################################################################
clean:
	@echo "[CLEAN] Removing build artifacts..."
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "[CLEAN] Removing *.req and *.rsp files in testvectors folder..."
	find testvectors -type f \( -name '*.req' -o -name '*.rsp' \) -delete

###############################################################################
# 4) rebuild : clean + build
###############################################################################
rebuild: clean build

###############################################################################
# 5) valgrind : run the binary under Valgrind for memory checking
###############################################################################
valgrind: build
	@echo "[VALGRIND] Running Valgrind..."
	valgrind --leak-check=full ./$(BIN_DIR)/$(TARGET)

###############################################################################
# 6) asan : build with AddressSanitizer enabled and run
###############################################################################
asan: CFLAGS += -fsanitize=address
asan: clean build
	@echo "[ASAN] Running with AddressSanitizer..."
	./$(BIN_DIR)/$(TARGET)

###############################################################################
# 7) gdb : Build with debugging symbols and launch GDB for in-depth inspection
###############################################################################
gdb: CFLAGS += -g
gdb: clean build
	@echo "[GDB] Launching GDB..."
	gdb $(BIN_DIR)/$(TARGET)

###############################################################################
# 8) inspect : Inspect the binary with nm and objdump
###############################################################################
inspect: build
	@echo "[INSPECT] Listing symbols with nm..."
	nm $(BIN_DIR)/$(TARGET)
	@echo "[INSPECT] Listing symbols with objdump..."
	objdump -t $(BIN_DIR)/$(TARGET)