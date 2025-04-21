/* File: src/mode/mode_ecb.c */

/**
 * @file mode_ecb.c
 * @brief This file implements the ECB (Electronic Codebook) mode of operation for block ciphers.
 * @details The ECB mode is a simple and straightforward mode of operation for block ciphers.
 */

#include "../../include/mode/mode_api.h"
#include "../../include/mode/mode_ecb.h"

/* Forward declarations of static functions. */
static void ecb_init(ModeOfOperationContext *ctx,
                     const BlockCipherApi *cipher_api,
                     const u8 *key, size_t key_len,
                     const u8 *iv, size_t iv_len,
                     BlockCipherDirection dir);
static void ecb_process(ModeOfOperationContext *ctx,
                        const u8 *in, u8 *out, size_t len,
                        BlockCipherDirection dir);
static void ecb_dispose(ModeOfOperationContext *ctx);

/**
 * @brief The ECB mode of operation API.
 * @details This structure contains function pointers for the ECB mode operations.
 */
static const ModeOfOperationApi ECB_MODE_API = {
    .name = "ECB",
    .init = ecb_init,
    .process = ecb_process,
    .dispose = ecb_dispose
};

const ModeOfOperationApi *get_ecb_api(void) { return &ECB_MODE_API; }

static void ecb_init(ModeOfOperationContext *ctx,
                              const BlockCipherApi *cipher_api,
                              const u8 *key, size_t key_len,
                              const u8 *iv, size_t iv_len,
                              BlockCipherDirection dir) {
    if (!ctx || !cipher_api || !key) {
        // fprintf(stderr, "Invalid context, cipher API, or key pointer\n");
        return;
    }
    if (iv || iv_len) {
        // fprintf(stderr, "ECB mode does not use IV\n");
        return;
    }
    if (key_len != 16) {
        // fprintf(stderr, "Invalid key length for ECB mode: %zu\n", key_len);
        return;
    }
    if (dir != BLOCK_CIPHER_ENCRYPTION && dir != BLOCK_CIPHER_DECRYPTION) {
        fprintf(stderr, "Invalid direction for ECB mode: %s\n", block_cipher_type_to_string(dir));
        return;
    }

    // Initialize the context with the cipher API and key
    // cipher_api->get_aes_api();
    // cipher_api->init(&ctx->cipher_ctx, key, key_len, 16, dir);
    // ctx->internal_data.ecb.dummy = 0; // ECB has no internal state
    ctx->api = &ECB_MODE_API;
    ctx->cipher_ctx.api = cipher_api;

    // Initialize the context with the cipher API and key

    
    
    
    // if (!ctx || !cipher_api || !key) return MODE_ERROR_INVALID_PARAM;
    // ctx->mode = MODE_ECB;
    // ctx->api = &ECB_MODE_API;
    // cipher_api->init(&ctx->cipher_ctx, key, key_len, 16, dir);
}

static void ecb_process(ModeOfOperationContext *ctx,
                                 const u8 *in, u8 *out, size_t len,
                                 BlockCipherDirection dir) {
    // if (!ctx || !in || !out) return MODE_ERROR_INVALID_PARAM;
    // size_t block_size = 16;
    // size_t num_blocks = len / block_size;
    // for (size_t i = 0; i < num_blocks; i++) {
    //     ctx->cipher_ctx.api->process_block(&ctx->cipher_ctx,
    //         in + i * block_size, out + i * block_size, dir);
    // }
    // return MODE_OK;
}

static void ecb_dispose(ModeOfOperationContext *ctx) {
    // if (ctx) ctx->cipher_ctx.api->dispose(&ctx->cipher_ctx);
}





// static block_cipher_mode_status_t ecb_encrypt(BlockCipherModeContext* ctx, const u8* input, u8* output, size_t length) {
//     if (!ctx || !input || !output || length % 16 != 0) {
//         return BLOCK_CIPHER_MODE_ERR_INVALID_INPUT;
//     }

//     for (size_t i = 0; i < length; i += 16) {
//         if (ctx->cipher_context->api->process_block(ctx->cipher_context, input + i, output + i, BLOCK_CIPHER_ENCRYPTION) != BLOCK_CIPHER_OK) {
//             return BLOCK_CIPHER_MODE_ERR_INVALID_INPUT;
//         }
//     }

//     return BLOCK_CIPHER_MODE_OK;
// }

// static block_cipher_mode_status_t ecb_decrypt(BlockCipherModeContext* ctx, const u8* input, u8* output, size_t length) {
//     if (!ctx || !input || !output || length % 16 != 0) {
//         return BLOCK_CIPHER_MODE_ERR_INVALID_INPUT;
//     }

//     for (size_t i = 0; i < length; i += 16) {
//         if (ctx->cipher_context->api->process_block(ctx->cipher_context, input + i, output + i, BLOCK_CIPHER_DECRYPTION) != BLOCK_CIPHER_OK) {
//             return BLOCK_CIPHER_MODE_ERR_INVALID_INPUT;
//         }
//     }

//     return BLOCK_CIPHER_MODE_OK;
// }

// block_cipher_mode_status_t mode_encrypt(BlockCipherModeContext* ctx, const u8* input, u8* output, size_t length) {
//     if (!ctx || ctx->mode != MODE_ECB) {
//         return BLOCK_CIPHER_MODE_ERR_UNSUPPORTED_MODE;
//     }
//     return ecb_encrypt(ctx, input, output, length);
// }

// block_cipher_mode_status_t mode_decrypt(BlockCipherModeContext* ctx, const u8* input, u8* output, size_t length) {
//     if (!ctx || ctx->mode != MODE_ECB) {
//         return BLOCK_CIPHER_MODE_ERR_UNSUPPORTED_MODE;
//     }
//     return ecb_decrypt(ctx, input, output, length);
// }