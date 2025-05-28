#include "config.h"
#include "mem.h"

int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len) {
    size_t i;
    const u8 *a = in_a;
    const u8 *b = in_b;
    u8 x = 0;

    for (i = 0; i < len; i++)
        x |= a[i] ^ b[i];

    return x;
}