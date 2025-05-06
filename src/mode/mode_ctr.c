/* FILE: src/mode/mode_ctr.c */
/**
 * @file mode_ctr.c
 * @brief This file implements the CTR (Counter) mode of operation for block ciphers.
 * @details The CTR mode is a widely used mode of operation for block ciphers.
 *          It provides confidentiality by using a counter to generate a unique keystream for each block.
 */

#include "../../include/block_cipher/api_block_cipher.h"
#include "../../include/mode/api_mode.h"
#include "../../include/mode/mode_ctr.h"

static void ctr_init(
    ModeOfOperationContext *mode_ctx, 
    const u8 *key, size_t key_len,
    const u8 *iv, size_t iv_len,
    u8 *in, size_t in_len,
    BlockCipherDirection dir);
static void ctr_process(
    ModeOfOperationContext *mode_ctx,
    const u8 *in, u8 *out, size_t padded_len,
    BlockCipherDirection dir);
static void ctr_dispose(ModeOfOperationContext *mode_ctx);

static const ModeOfOperationApi CTR_MODE_API = {
    .mode_name = "CTR",
    .mode_init = ctr_init,
    .mode_process = ctr_process,
    .mode_process_with_tag = NULL,  // use ctr_encrypt_with_tag directly
    .mode_dispose = ctr_dispose
};

const ModeOfOperationApi *get_ctr_api(void) { return &CTR_MODE_API; }

void ctr_init(
    ModeOfOperationContext *mode_ctx,
    const u8 *key, size_t key_len,
    const u8 *iv, size_t iv_len,
    u8 *in, size_t in_len,
    BlockCipherDirection dir) {
    
    // Initialize the CTR mode context
    if (!mode_ctx || !key || !iv) {
        fprintf(stderr, "Invalid mode context, key or IV pointer\n");
        return;
    }
    
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        fprintf(stderr, "Invalid key length for CTR mode: %zu\n", key_len);
        return;
    }
    
    if (iv_len != BLOCK_SIZE) {
        fprintf(stderr, "Invalid IV length for CTR mode: %zu\n", iv_len);
        return;
    }
    
    // Set the mode type and cipher type
    mode_ctx->mode_type = MODE_CTR;
    mode_ctx->cipher_type = mode_ctx->cipher_type;
    size_t padded_len = iso7816_4_pad(in, in_len, BLOCK_SIZE);
    in_len = padded_len;
    
    // Initialize the block cipher context
    mode_ctx->cipher_ctx = malloc(sizeof(BlockCipherContext));
    if (!mode_ctx->cipher_ctx) {
        fprintf(stderr, "Failed to allocate memory for cipher context\n");
        return;
    }
    
    // Initialize the block cipher API
    mode_ctx->cipher_ctx->cipher_api = block_cipher_factory("AES");
    
    // Initialize the block cipher with the provided key and IV
    if (mode_ctx->cipher_ctx->cipher_api->cipher_init(
            mode_ctx->cipher_ctx, key, key_len, BLOCK_SIZE, dir) != BLOCK_CIPHER_OK) {
        fprintf(stderr, "Error initializing block cipher context\n");
        free(mode_ctx->cipher_ctx);
        return;
    }
    
    // Copy the IV into the internal state
    memcpy(mode_ctx->mode_state.ctr_internal.counter, iv, BLOCK_SIZE);
}

void ctr_process(
    ModeOfOperationContext *mode_ctx,
    const u8 *in, u8 *out, size_t padded_len,
    BlockCipherDirection dir) {
    
    // Check for valid input
    if (!mode_ctx || !in || !out) {
        fprintf(stderr, "Invalid mode context or input/output pointers\n");
        return;
    }
    
    // Process the input data using the CTR mode
    size_t block_size = BLOCK_SIZE;
    size_t num_blocks = padded_len / block_size;
    
    for (size_t i = 0; i < num_blocks; i++) {
        // Encrypt the counter value
        u8 counter_block[BLOCK_SIZE];
        memcpy(counter_block, mode_ctx->mode_state.ctr_internal.counter, BLOCK_SIZE);
        
        // Increment the counter
        for (int j = BLOCK_SIZE - 1; j >= 0; j--) {
            if (++counter_block[j] != 0) break;
        }
        
        // Encrypt the counter block
        mode_ctx->cipher_ctx->cipher_api->cipher_process(
            mode_ctx->cipher_ctx, counter_block, out + (i * block_size), dir);
        
        // XOR with the input block
        for (size_t k = 0; k < block_size; k++) {
            out[i * block_size + k] ^= in[i * block_size + k];
        }
        
        // Update the counter in the internal state
        memcpy(mode_ctx->mode_state.ctr_internal.counter, counter_block, BLOCK_SIZE);
    }
}

void ctr_dispose(ModeOfOperationContext *mode_ctx) {
    if (mode_ctx) {
        // Dispose of the cipher context
        if (mode_ctx->cipher_ctx && mode_ctx->cipher_ctx->cipher_api->cipher_dispose) {
            mode_ctx->cipher_ctx->cipher_api->cipher_dispose(mode_ctx->cipher_ctx);
        }
        // Clear the context memory
        memset(mode_ctx, 0, sizeof(*mode_ctx));
        free(mode_ctx->cipher_ctx);
    }
}