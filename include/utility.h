/* include/utility.h */

#include "api.h"
// #include "block_cipher/block_cipher.h"

static inline void clear_ctx(BlockCipherContext *ctx) {
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}
