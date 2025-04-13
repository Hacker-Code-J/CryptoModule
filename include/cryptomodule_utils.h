/* File: include/utility.h */

#include "cryptomodule_api.h"
// #include "block_cipher/block_cipher.h"

#ifndef UTILITY_H
#define UTILITY_H

#ifdef __cplusplus
extern "C" {
#endif

static inline void clear_ctx(BlockCipherContext *ctx) {
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

void stringToByteArray(const char* str, u8* byteArray);
void stringToWordArray(const char* str, u32* wordArray);

#ifdef __cplusplus
}
#endif

#endif /* UTILITY_H */