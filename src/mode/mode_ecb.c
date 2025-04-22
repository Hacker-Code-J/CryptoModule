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
    const u8 *in, u8 *out, size_t data_tot_len,
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
    const u8 *in, u8 *out, size_t data_tot_len,
    BlockCipherDirection dir) {
    
    if (!mode_ctx || !in || !out) {
        fprintf(stderr, "Invalid mode context or input/output pointers\n");
        return;
    }
    if (data_tot_len % BLOCK_SIZE != 0) {
        fprintf(stderr, "Invalid data length for ECB mode: %zu\n", data_tot_len);
        return;
    }
    if (mode_ctx->cipher_ctx->cipher_api->cipher_process(
            mode_ctx->cipher_ctx, in, out, dir) != BLOCK_CIPHER_OK) {
        fprintf(stderr, "Error processing block in ECB mode\n");
        return;
    }

    // Update the total length of data processed
    // mode_ctx->total_len += data_tot_len;
    // Clear the buffer
    memset(mode_ctx->buffer, 0, sizeof(mode_ctx->buffer));
    mode_ctx->buffer_len = 0; // No buffered data
    mode_ctx->mode_internal_data.ecb_internal.dummy = 0; // ECB has no internal state
    
    // Process the input data for each block
    for (size_t i = 0; i < data_tot_len; i += BLOCK_SIZE) {
        if (mode_ctx->cipher_ctx->cipher_api->cipher_process(
                mode_ctx->cipher_ctx, in + i, out + i, dir) != BLOCK_CIPHER_OK) {
            fprintf(stderr, "Error processing block in ECB mode\n");
            return;
        }
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