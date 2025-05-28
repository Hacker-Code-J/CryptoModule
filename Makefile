# Compact Makefile for CryptoModule
CC       := gcc
CFLAGS   := -std=c99 -O2 -Wall -Wextra -Iinclude
SRCDIR   := src
OBJDIR   := obj
TARGET   := CryptoModule

SOURCES  := $(SRCDIR)/main.c \
	$(SRCDIR)/block/aes.c \
	$(SRCDIR)/common/mem.c \
	$(SRCDIR)/mode/cbc128.c $(SRCDIR)/mode/ctr128.c $(SRCDIR)/mode/gcm128.c
OBJECTS  := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
DEPS     := $(OBJECTS:.o=.d)

.PHONY: all run clean rebuild
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

run: all
	./$(TARGET)

clean:
	rm -rf $(OBJDIR) $(TARGET)

rebuild: clean all
