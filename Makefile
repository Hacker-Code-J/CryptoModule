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

# # -------------------------------------------------------------------
# # Advanced Makefile with Dedicated Object Directory and Explicit main.c
# #
# # This Makefile:
# #  - Recursively finds all .c source files under the src/ directory.
# #  - Places object (.o) and dependency (.d) files in a separate obj/ folder,
# #    maintaining the subdirectory structure.
# #  - Ensures the executable is built from src/main.c.
# #  - Generates dependency files so header changes trigger recompilations.
# #  - Provides targets: build, run, clean, and rebuild.
# # -------------------------------------------------------------------

# # Compiler and flags
# CC      := gcc
# CFLAGS  := -Wall -Wextra -O2 -Iinclude -MMD -MP
# LDFLAGS :=
# TARGET  := app

# # Directories
# SRCDIR := src
# OBJDIR := obj

# # Automatically find all .c source files and map them to objects in OBJDIR
# SOURCES := $(shell find $(SRCDIR) -name '*.c')
# OBJECTS := $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SOURCES))
# DEPS    := $(OBJECTS:.o=.d)

# # Ensure that src/main.c exists among the sources
# ifeq ($(wildcard $(SRCDIR)/main.c),)
# $(error "Error: src/main.c not found. Please ensure the main source file exists.")
# endif

# # Phony targets
# .PHONY: all build run clean rebuild

# # Default target: build
# all: build

# # Build target: compile the executable from object files,
# # ensuring the object from src/main.c (i.e. obj/main.o) is first.
# build: $(TARGET)

# $(TARGET): $(OBJDIR)/main.o $(filter-out $(OBJDIR)/main.o, $(OBJECTS))
# 	@echo "Linking objects to create $(TARGET)..."
# 	$(CC) $^ -o $(TARGET) $(LDFLAGS)

# # Generic rule for compiling .c files to .o files in the object directory
# $(OBJDIR)/%.o: $(SRCDIR)/%.c
# # @echo "Compiling $<..."
# 	@mkdir -p $(dir $@)
# 	$(CC) $(CFLAGS) -c $< -o $@

# # Run target: build (if needed) then execute the program
# run: build
# 	@echo "Running $(TARGET)..."
# 	./$(TARGET)

# # Clean target: remove the object directory and the executable
# clean:
# 	@echo "Cleaning object files and executable..."
# 	rm -rf $(OBJDIR) $(TARGET)

# # Rebuild target: clean then build
# rebuild: clean build

# # Include dependency files (if they exist)
# -include $(DEPS)


# ##############################################################################
# # Makefile for Block Cipher components only
# # Produces: libblockcipher.a
# # Optional: test_block (if test_block.c is present)
# ##############################################################################

# CC       := gcc
# AR       := ar
# RANLIB   := ranlib

# # Change include path as needed
# CFLAGS   := -Wall -O2 -Iinclude

# # Source files for block ciphers
# BLOCK_SOURCES := \
#     block_cipher_aes.c \
#     # block_cipher_aria.c \
#     # block_cipher_lea.c \
#     # block_cipher_factory.c

# # Build a static library from them
# LIB_NAME := libblockcipher.a

# # If you want to build a test, name it here
# TEST_SOURCE := src/block/main.c
# TEST_BIN    := test_block

# ##############################################################################
# # Build object lists
# ##############################################################################
# BLOCK_OBJS := $(BLOCK_SOURCES:.c=.o)
# TEST_OBJ   := $(TEST_SOURCE:.c=.o)

# ##############################################################################
# # Default target: library and optional test
# ##############################################################################
# .PHONY: all
# all: $(LIB_NAME) test

# ##############################################################################
# # Create the static library
# ##############################################################################
# $(LIB_NAME): $(BLOCK_OBJS)
# 	@echo "[AR]  $@"
# 	$(AR) rcs $@ $^
# 	$(RANLIB) $@

# ##############################################################################
# # Compile rules
# ##############################################################################
# %.o: %.c
# 	@echo "[CC]  $<"
# 	$(CC) $(CFLAGS) -c $< -o $@

# ##############################################################################
# # Build and link test executable (optional)
# ##############################################################################
# .PHONY: test
# test: $(TEST_BIN)

# $(TEST_BIN): $(TEST_OBJ) $(LIB_NAME)
# 	@echo "[LD]  $@"
# 	$(CC) $(CFLAGS) $^ -o $@

# ##############################################################################
# # Cleaning up
# ##############################################################################
# .PHONY: clean
# clean:
# 	rm -f *.o $(LIB_NAME) $(TEST_BIN)


# # File: Makefile
# CC         = gcc
# AR         = ar
# RANLIB     = ranlib
# CFLAGS     = -O2 -Wall -I./include
# LIB_NAME   = libcryptomodule.a

# SRC_DIR    = src
# INCLUDE    = include
# TEST_DIR   = tests
# OBJ_DIR    = obj
# BIN_DIR    = bin

# # Collect all .c files in src/
# SRC_FILES  = $(wildcard $(SRC_DIR)/*.c)
# OBJ_FILES  = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC_FILES))

# # Tests
# TESTS      = test_aes test_gcm test_main
# TEST_OBJS  = $(patsubst %, $(OBJ_DIR)/%.o, $(TESTS))
# TEST_BINS  = $(patsubst %, $(BIN_DIR)/%, $(TESTS))

# .PHONY: all clean test

# all: $(LIB_NAME) test

# $(LIB_NAME): $(OBJ_FILES)
# 	@echo "  AR    $@"
# 	$(AR) rcs $@ $^
# 	$(RANLIB) $@

# # Compile *.c -> *.o
# $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
# 	@mkdir -p $(OBJ_DIR)
# 	@echo "  CC    $<"
# 	$(CC) $(CFLAGS) -c $< -o $@

# # Build test object files
# $(OBJ_DIR)/%.o: $(TEST_DIR)/%.c
# 	@mkdir -p $(OBJ_DIR)
# 	@echo "  CC    $<"
# 	$(CC) $(CFLAGS) -c $< -o $@

# # Link test binaries
# $(BIN_DIR)/%: $(OBJ_DIR)/%.o $(LIB_NAME)
# 	@mkdir -p $(BIN_DIR)
# 	@echo "  LD    $@"
# 	$(CC) $(CFLAGS) $< -o $@ -L. -lcryptomodule

# test: $(TEST_BINS)
# 	@echo "Build test executables done."

# clean:
# 	rm -rf $(OBJ_DIR) $(BIN_DIR) $(LIB_NAME)



# CC          := gcc
# AR          := ar
# RANLIB      := ranlib
# CFLAGS      := -O2 -Wall -I./include
# LIB_NAME    := libcryptomodule.a

# BUILD_DIR   := build
# OBJ_DIR     := $(BUILD_DIR)/obj
# BIN_DIR     := $(BUILD_DIR)/bin

# # --------------------------------------------------------------------------
# # 1) Collect all .c files by categories
# # --------------------------------------------------------------------------
# BLOCK_SRCS  := $(wildcard src/block/*.c)
# MODE_SRCS   := $(wildcard src/mode/*.c)
# RNG_SRCS    := $(wildcard src/rng/*.c)
# HASH_SRCS   := $(wildcard src/hash/*.c)
# MAC_SRCS    := $(wildcard src/mac/*.c)
# KDF_SRCS    := $(wildcard src/kdf/*.c)
# KEYSETUP_SRCS := $(wildcard src/keysetup/*.c)
# SIGN_SRCS   := $(wildcard src/sign/*.c)

# SRCS_ALL    := $(BLOCK_SRCS) $(MODE_SRCS) $(RNG_SRCS) \
#                $(HASH_SRCS)  $(MAC_SRCS)  $(KDF_SRCS) \
#                $(KEYSETUP_SRCS) $(SIGN_SRCS)

# OBJS_ALL    := $(patsubst src/%.c, $(OBJ_DIR)/%.o, $(SRCS_ALL))

# # Test sources
# TEST_SRCS   := $(wildcard tests/*.c)
# TEST_OBJS   := $(patsubst tests/%.c, $(OBJ_DIR)/%.o, $(TEST_SRCS))
# TEST_BINS   := $(patsubst tests/%.c, $(BIN_DIR)/%,  $(TEST_SRCS))

# .PHONY: all clean test run-tests

# all: $(LIB_NAME) test

# # --------------------------------------------------------------------------
# # 2) Build the static library
# # --------------------------------------------------------------------------
# $(LIB_NAME): $(OBJS_ALL)
# 	@echo "[AR]  $@"
# 	$(AR) rcs $@ $^
# 	$(RANLIB) $@

# $(OBJ_DIR)/%.o: src/%.c
# 	@mkdir -p $(dir $@)
# 	@echo "[CC]  $<"
# 	$(CC) $(CFLAGS) -c $< -o $@

# # --------------------------------------------------------------------------
# # 3) Build test executables
# # --------------------------------------------------------------------------
# test: $(TEST_BINS)

# $(OBJ_DIR)/%.o: tests/%.c
# 	@mkdir -p $(dir $@)
# 	@echo "[CC]  $<"
# 	$(CC) $(CFLAGS) -c $< -o $@

# $(BIN_DIR)/%: $(OBJ_DIR)/%.o $(LIB_NAME)
# 	@mkdir -p $(dir $@)
# 	@echo "[LD]  $@"
# 	$(CC) $(CFLAGS) $< -o $@ -L. -lcryptomodule

# run-tests: test
# 	@for t in $(TEST_BINS); do echo "Running $$t"; $$t || exit 1; done

# clean:
# 	rm -rf $(BUILD_DIR) $(LIB_NAME)
