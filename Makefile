# Makefile at project root (my_ecdsa/)

FLINT_CFLAGS := $(shell pkg-config --cflags flint)
FLINT_LIBS   := $(shell pkg-config --libs flint)

CC := gcc
CFLAGS := -O2 -Wall -Wextra -Iinclude $(FLINT_CFLAGS)
LDFLAGS := $(FLINT_LIBS)

LIB_OBJS := src/ecdsa.o
LIB := libecdsa.a

all: $(LIB) test_ecdsa

$(LIB): $(LIB_OBJS)
	ar rcs $@ $^

test_ecdsa: src/test_ecdsa.o $(LIB)
	$(CC) -o $@ src/test_ecdsa.o -L. -lecdsa $(LDFLAGS)

src/ecdsa.o: src/ecdsa.c src/ecdsa.h
	$(CC) $(CFLAGS) -c src/ecdsa.c -o $@

src/test_ecdsa.o: src/test_ecdsa.c src/ecdsa.h
	$(CC) $(CFLAGS) -c src/test_ecdsa.c -o $@

clean:
	rm -f $(LIB) test_ecdsa src/*.o
