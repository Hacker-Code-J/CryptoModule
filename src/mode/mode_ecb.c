/* File: src/mode/mode_ecb.c */

/**
 * @file mode_ecb.c
 * @brief This file implements the ECB (Electronic Codebook) mode of operation for block ciphers.
 * @details The ECB mode is a simple and straightforward mode of operation for block ciphers.
 */

#include "../../include/mode/mode_api.h"
#include "../../include/mode/mode_ecb.h"
#include "../../include/block_cipher/block_cipher_api.h"

/* Forward declarations of static functions. */
static void ecb_init(ModeOfOperationContext *mode_ctx, 
    BlockCipherType cipher_type,
    const u8 *key, size_t key_len,
    const u8 *iv, size_t iv_len,
    u8 *in, size_t in_len,
    BlockCipherDirection dir);
static void ecb_update(ModeOfOperationContext *mode_ctx,
    const u8 *in, size_t in_len,
    u8 *out, size_t out_len,
    BlockCipherDirection dir);
            
static void ecb_dispose(ModeOfOperationContext *mode_ctx);


/**
 * @brief The ECB mode of operation API.
 * @details This structure contains function pointers for the ECB mode operations.
 */
static const ModeOfOperationApi ECB_MODE_API = {
    .mode_name = "ECB",
    .mode_init = ecb_init,
    .mode_update = ecb_update,
    .mode_update_auth = NULL, // ECB does not require authentication
    .mode_finalize = NULL, // ECB does not require a finalize step
    .mode_finalize_auth = NULL, // ECB does not require authentication
    .mode_dispose = ecb_dispose
};

const ModeOfOperationApi *get_ecb_api(void) { return &ECB_MODE_API; }

static void ecb_init(ModeOfOperationContext *mode_ctx,
    BlockCipherType cipher_type,
    const u8 *key, size_t key_len,
    const u8 *iv, size_t iv_len,
    u8 *in, size_t in_len,
    BlockCipherDirection dir) {
    // Initialize the ECB mode context
    if (!mode_ctx || !key) {
        fprintf(stderr, "Invalid mode context, or key pointer\n");
        return;
    }
    if (iv || iv_len) {
        fprintf(stderr, "ECB mode does not use IV\n");
        return;
    }
    if (key_len != 16) {
        fprintf(stderr, "Invalid key length for ECB mode: %zu\n", key_len);
        return;
    }

    mode_ctx->mode_api = mode_factory("ECB");
    mode_ctx->cipher_ctx = (BlockCipherContext*)malloc(sizeof(BlockCipherContext));
    if (!mode_ctx->cipher_ctx) {
        fprintf(stderr, "Failed to allocate memory for cipher context\n");
        return;
    }

    // mode_ctx->cipher_ctx->cipher_api->cipher_init(
    //     mode_ctx->cipher_ctx, key, key_len, BLOCK_SIZE, dir);
    // mode_ctx->block_size = BLOCK_SIZE;
    // mode_ctx->buffer_len = 0; // No buffered data
    // mode_ctx->total_len = 0; // Total length of data processed
    // mode_ctx->mode_internal_data.ecb_internal.dummy = 0; // ECB has no internal state

    size_t total_block_size = iso7816_4_pad(in, in_len, BLOCK_SIZE);
    if (total_block_size % BLOCK_SIZE != 0) {
        fprintf(stderr, "Invalid input length for ECB mode: %zu\n", total_block_size);
        return;
    }
    mode_ctx->total_len = total_block_size;
    
    block_cipher_status_t status = BLOCK_CIPHER_OK;
    if (cipher_type == BLOCK_CIPHER_AES128) {
        if (key_len != AES128_KEY_SIZE) {
            fprintf(stderr, "Invalid key length for AES-128: %zu\n", key_len);
            return;
        }

        mode_ctx->cipher_ctx->cipher_api = block_cipher_factory("AES");
        if (!mode_ctx->cipher_ctx->cipher_api) {
            fprintf(stderr, "Failed to create AES cipher API\n");
            free(mode_ctx->cipher_ctx);
            return;
        }
        status = mode_ctx->cipher_ctx->cipher_api->cipher_init(
            mode_ctx->cipher_ctx, key, key_len, BLOCK_SIZE, dir);
        if (status != BLOCK_CIPHER_OK) {
            fprintf(stderr, "Error initializing AES context\n");
            free(mode_ctx->cipher_ctx);
            return;
        }

    } else if (cipher_type == BLOCK_CIPHER_AES192) {

    } else if (cipher_type == BLOCK_CIPHER_AES256) {

    } else {
        fprintf(stderr, "Unsupported cipher type for ECB mode: %d\n", cipher_type);
        return;
    }

}

static void ecb_update(
    ModeOfOperationContext *mode_ctx,
    const u8 *in, size_t in_len,
    u8 *out, size_t out_len,
    BlockCipherDirection dir) {
    
    
    mode_ctx->block_size = BLOCK_SIZE;
    size_t block_size = mode_ctx->block_size;

    printf("ECB Update: in_len=%zu, out_len=%zu\n", in_len, out_len);
    printf("ECB Update: buffer_len=%zu\n", mode_ctx->buffer_len);
    printf("ECB Update: block_size=%zu\n", block_size);

    // Process any previously buffered bytes with new input to make a full block
    if (mode_ctx->buffer_len > 0) {
        size_t needed = block_size - mode_ctx->buffer_len;
        if (in_len >= needed) {
            // fill the buffer to make a full block
            for (size_t i = 0; i < needed; ++i) {
                mode_ctx->buffer[mode_ctx->buffer_len + i] = in[i];
            }
            in += needed;
            in_len -= needed;
            mode_ctx->buffer_len += needed;
            // Now buffer has a full block
            mode_ctx->cipher_ctx->cipher_api->cipher_process(mode_ctx->cipher_ctx, mode_ctx->buffer, out, dir);
            out_len += block_size;
            mode_ctx->buffer_len = 0;
            out += block_size;
        } else {
            // Not enough to complete a block, store input in buffer and return
            for (size_t i = 0; i < in_len; ++i) {
                mode_ctx->buffer[mode_ctx->buffer_len + i] = in[i];
            }
            mode_ctx->buffer_len += in_len;
            // return true; // output_lten remains 0 (no new output yet)
        }
    }

    printf("%zu bytes (in_len )\n", in_len);
    printf("%zu bytes (out_len)\n", out_len);
    printf("%zu bytes (block_size)\n", block_size);

    // Process full blocks from remaining input
    // while (in_len >= block_size) {
    //     printf("%zu bytes left to process\n", in_len);
    //     printf("%zu bytes left to write\n", out_len);
    //     printf("%zu bytes for block size\n", block_size);
    //     mode_ctx->cipher_ctx->cipher_api->cipher_process(mode_ctx->cipher_ctx, in, out, dir);
    //     in += block_size;
    //     in_len -= block_size;
    //     out_len += block_size;
    //     out += block_size;
    // }
    // Buffer any leftover partial block

    if (in_len > 0) {
        for (size_t i = 0; i < in_len; ++i) {
            mode_ctx->buffer[i] = in[i];
        }
        mode_ctx->buffer_len = in_len;
    }
}

static void ecb_dispose(ModeOfOperationContext *mode_ctx) {
    if (mode_ctx) {
        // Dispose of the cipher context
        // if (ctx->api && ctx->cipher_ctx.api->dispose) {
        //     ctx->cipher_ctx.api->dispose(&ctx->cipher_ctx);
        // }
        // Clear the context memory
        memset(mode_ctx, 0, sizeof(*mode_ctx));
    }
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