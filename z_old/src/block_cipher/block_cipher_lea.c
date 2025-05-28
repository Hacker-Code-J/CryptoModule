/* FILE: src/block_cipher/block_cipher_lea.c */
/**
 * @file block_cipher_lea.c
 * @brief This file implements LEA encryption and decryption operations.
 * @details The implementation in this source code file references the following site:
 *          https://seed.kisa.or.kr/kisa/Board/20/detailView.do
 */

#include "../../include/block_cipher/block_cipher_lea.h"

/* Forward declarations of static functions. */
static block_cipher_status_t lea_init(BlockCipherContext *ctx, const u8 *key, size_t key_len, size_t block_len, BlockCipherDirection dir);
static block_cipher_status_t lea_process(BlockCipherContext *ctx, const u8 *in, u8 *out, BlockCipherDirection dir);
static void lea_dispose(BlockCipherContext *ctx);

/**
 * @brief The LEA block cipher API.
 * @details This structure contains function pointers to the LEA initialization, unified encryption/decryption function,
 *          and disposal functions.
 */
static const BlockCipherApi LEA_API = {
    .cipher_name          = "LEA",
    .cipher_init          = lea_init,
    .cipher_process       = lea_process,
    .cipher_dispose       = lea_dispose
};
/**
 * @brief Get the LEA block cipher API.
 * @return Pointer to the LEA block cipher API structure.
 */
const BlockCipherApi *get_lea_api(void) { return &LEA_API; }

block_cipher_status_t lea_init(BlockCipherContext *ctx, const u8 *key, size_t key_len, size_t block_len, BlockCipherDirection dir) {
    if (!ctx || !key || key_len == 0 || block_len != LEA_BLOCK_SIZE) {
        return BLOCK_CIPHER_INVALID_PARAMETER;
    }

    ctx->cipher_api = get_lea_api();
    ctx->cipher_state.lea_internal.block_size = block_len;
    ctx->cipher_state.lea_internal.key_len = key_len;

    if (dir == BLOCK_CIPHER_ENCRYPTION) {
        lea_set_encrypt_key(key, key_len, ctx->cipher_state.lea_internal.round_keys);
    } else {
        lea_set_decrypt_key(key, key_len, ctx->cipher_state.lea_internal.round_keys);
    }

    return BLOCK_CIPHER_OK;
}
block_cipher_status_t lea_process(BlockCipherContext *ctx, const u8 *in, u8 *out, BlockCipherDirection dir) {
    if (!ctx || !in || !out) {
        return BLOCK_CIPHER_INVALID_PARAMETER;
    }

    if (dir == BLOCK_CIPHER_ENCRYPTION) {
        lea_encrypt(in, out, ctx->cipher_state.lea_internal.round_keys, ctx->cipher_state.lea_internal.nr);
    } else {
        lea_decrypt(in, out, ctx->cipher_state.lea_internal.round_keys, ctx->cipher_state.lea_internal.nr);
    }

    return BLOCK_CIPHER_OK;
}
void lea_dispose(BlockCipherContext *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
}

void lea_set_encrypt_key(const u8 *key, size_t bytes, u32 *rk) {
    return;
}
void lea_set_decrypt_key(const u8 *key, size_t bytes, u32 *rk) {
    return;
}
void lea_encrypt(const u8 *in, u8 *out, const u32 *rk, int r) {
    return;
}
void lea_decrypt(const u8 *in, u8 *out, const u32 *rk, int r) {
    return;
}