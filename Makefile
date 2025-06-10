#-------------------------------------------------------------------------------
# Makefile: separate obj/, lib/, bin/; builds libarith.a, libec.a, libsign.a
#-------------------------------------------------------------------------------

# Directories
OBJ_DIR   := obj
LIB_DIR   := lib
BIN_DIR   := bin
INCLUDE   := include
SRC_DIR   := src

# Compiler & tools
CC        := gcc
AR        := ar rcs
# RANLIB    := ranlib

# Flags
CFLAGS    := -MMD -MP -O3 -std=c99 -Wall -Wextra -I$(INCLUDE)
PICFLAGS  := -fPIC

# Module source files
FP_SRCS      := $(wildcard $(SRC_DIR)/fp/fp_*.c)
NN_SRCS      := $(wildcard $(SRC_DIR)/nn/nn_*.c) $(SRC_DIR)/nn/nn.c
UTILS_ARITH  := $(SRC_DIR)/utils/utils.c $(SRC_DIR)/utils/utils_rand.c
UTILS_PRINT  := $(wildcard $(SRC_DIR)/utils/print_*.c)
CURVES_SRCS  := $(wildcard $(SRC_DIR)/curves/*.c)
HASH_SRCS    := $(wildcard $(SRC_DIR)/hash/*.c)
SIG_SRCS     := $(SRC_DIR)/sig/ecdsa.c $(SRC_DIR)/sig/ecdsa_common.c $(SRC_DIR)/sig/sig_algs.c $(SRC_DIR)/sig/ec_key.c

# Generate object lists by mirroring src/ to obj/
define to_obj
  $(patsubst $(SRC_DIR)/%, $(OBJ_DIR)/%, $(1:.c=.o))
endef

FP_OBJS       := $(call to_obj,$(FP_SRCS))
NN_OBJS       := $(call to_obj,$(NN_SRCS))
UTILS_ARITH_OBJS := $(call to_obj,$(UTILS_ARITH))
UTILS_PRINT_OBJS := $(call to_obj,$(UTILS_PRINT))
CURVES_OBJS   := $(call to_obj,$(CURVES_SRCS))
HASH_OBJS     := $(call to_obj,$(HASH_SRCS))
SIG_OBJS      := $(call to_obj,$(SIG_SRCS))

# Library object groups
LIBARITH_OBJS := $(FP_OBJS) $(NN_OBJS) $(UTILS_ARITH_OBJS) $(UTILS_PRINT_OBJS)
LIBEC_OBJS    := $(LIBARITH_OBJS) $(CURVES_OBJS)
LIBSIGN_OBJS  := $(LIBEC_OBJS) $(HASH_OBJS) $(SIG_OBJS)

# All objects and deps
ALL_OBJS      := $(sort $(LIBSIGN_OBJS))
DEPS          := $(ALL_OBJS:.o=.d)

# Phony targets
.PHONY: all clean rebuild
all: $(LIB_DIR)/libarith.a $(LIB_DIR)/libec.a $(LIB_DIR)/libsign.a

clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)
	rm -f *~

# Compile rule: .c → .o (+ deps)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(PICFLAGS) -MMD -MP -c $< -o $@

# Static libraries
$(LIB_DIR)/libarith.a: $(LIBARITH_OBJS)
	@mkdir -p $(LIB_DIR)
	$(AR) $@ $^
# $(RANLIB) $@

$(LIB_DIR)/libec.a: $(LIBEC_OBJS)
	@mkdir -p $(LIB_DIR)
	$(AR) $@ $^
# $(RANLIB) $@

$(LIB_DIR)/libsign.a: $(LIBSIGN_OBJS)
	@mkdir -p $(LIB_DIR)
	$(AR) $@ $^
# $(RANLIB) $@

rebuild:
	$(MAKE) clean
	$(MAKE) -j8

# Include dependency files
-include $(DEPS)



# # Top-level directories
# SRCDIR := src
# OBJDIR := obj

# # Gather all .c files under src/
# SRC := $(shell find $(SRCDIR) -name '*.c')

# # Compute corresponding .o paths under obj/
# OBJ := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))

# CC      := gcc
# CFLAGS  := -Wextra -Wall -std=c99 -O3 -fPIC -MMD -MP -Iinclude/

# # Default target
# all: $(OBJ)

# # Pattern rule: build obj/…/file.o from src/…/file.c
# $(OBJDIR)/%.o: $(SRCDIR)/%.c
# 	mkdir -p $(dir $@)
# 	$(CC) $(CFLAGS) -c $< -o $@

# # Include dependency files
# -include $(OBJ:.o=.d)

# .PHONY: clean
# clean:
# 	rm -rf $(OBJDIR)

# # Top-level dirs
# SRCDIR   := src
# OBJDIR   := obj
# INCDIR   := include

# # Tools & flags
# CC       := gcc
# CFLAGS   := -Wextra -Wall -std=c99 -O3 -fPIC -MMD -MP -I$(INCDIR)

# # Discover all .c files under src/
# SRC      := $(shell find $(SRCDIR) -name '*.c')
# # Compute matching .o paths in obj/
# OBJ      := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))
# # Dependency files
# DEPS     := $(OBJ:.o=.d)

# # Static library name
# LIB      := libcrypto.a

# # Test sources & binary
# TEST_SRC := $(wildcard $(SRCDIR)/tests/*.c)
# TEST_OBJ := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(TEST_SRC))
# TEST_BIN := ec_self_tests

# .PHONY: all clean rebuild run

# # default builds the library
# all: $(LIB)

# # archive all object files into libcrypto.a
# $(LIB): $(OBJ)
# 	@echo "Archive → $@"
# 	ar rcs $@ $^

# # generic rule: compile src/.../*.c → obj/.../*.o
# $(OBJDIR)/%.o: $(SRCDIR)/%.c
# 	@mkdir -p $(dir $@)
# 	$(CC) $(CFLAGS) -c $< -o $@

# # include dependency files (header tracking)
# -include $(DEPS)

# # clean out everything
# clean:
# 	@echo "Cleaning"
# 	rm -rf $(OBJDIR) $(LIB) $(TEST_BIN)

# # rebuild = clean + all
# rebuild: clean all

# # build test executable by linking your library + test objects
# $(TEST_BIN): $(OBJ) $(TEST_OBJ)
# 	@echo "Link test → $@"
# 	$(CC) $(CFLAGS) -o $@ $(TEST_OBJ) $(OBJ)

# # run the tests
# run: $(TEST_BIN)
# 	@echo "Running $(TEST_BIN):"
# 	./$(TEST_BIN)
