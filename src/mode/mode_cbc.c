/* FILE: src/mode/mode_cbc.c */
/**
 * @file mode_cbc.c
 * @brief This file implements the CBC (Cipher Block Chaining) mode of operation for block ciphers.
 * @details The CBC mode is a widely used mode of operation for block ciphers.
 *          It provides confidentiality by chaining the encryption of each block with the previous block's ciphertext.
 */

#include "../../include/block_cipher/api_block_cipher.h"
#include "../../include/mode/api_mode.h"
#include "../../include/mode/mode_cbc.h"

static void cbc_init(
    ModeOfOperationContext *mode_ctx,
    const u8 *key, size_t key_len,
    const u8 *iv, size_t iv_len,
    u8 *in, size_t in_len,
    BlockCipherDirection dir);
static void cbc_process(
    ModeOfOperationContext *mode_ctx,
    const u8 *in, u8 *out, size_t padded_len,
    BlockCipherDirection dir);
static void cbc_dispose(ModeOfOperationContext *mode_ctx);

static const ModeOfOperationApi CBC_MODE_API = {
    .mode_name = "CBC",
    .mode_init = cbc_init,
    .mode_process = cbc_process,
    .mode_process_with_tag = NULL,  // use cbc_encrypt_with_tag directly
    .mode_dispose = cbc_dispose
};

const ModeOfOperationApi *get_cbc_api(void) { return &CBC_MODE_API; }

void cbc_init(
    ModeOfOperationContext *mode_ctx,
    const u8 *key, size_t key_len,
    const u8 *iv, size_t iv_len,
    u8 *in, size_t in_len,
    BlockCipherDirection dir) {
    
    // Initialize the CBC mode context
    if (!mode_ctx || !key || !iv) {
        fprintf(stderr, "Invalid mode context, key or IV pointer\n");
        return;
    }
    
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        fprintf(stderr, "Invalid key length for CBC mode: %zu\n", key_len);
        return;
    }
    
    if (iv_len != BLOCK_SIZE) {
        fprintf(stderr, "Invalid IV length for CBC mode: %zu\n", iv_len);
        return;
    }
    
    // Set the mode type and cipher type
    mode_ctx->mode_type = MODE_CBC;
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
    memcpy(mode_ctx->mode_state.cbc_internal.iv, iv, BLOCK_SIZE);
}

void cbc_process(
    ModeOfOperationContext *mode_ctx,
    const u8 *in, u8 *out, size_t padded_len,
    BlockCipherDirection dir) {
    
    if (!mode_ctx || !in || !out) {
        fprintf(stderr, "Invalid mode context or input/output pointers\n");
        return;
    }
    
    if (padded_len % BLOCK_SIZE != 0) {
        fprintf(stderr, "Invalid padded length for CBC mode: %zu\n", padded_len);
        return;
    }
    
    // Process the input data for each block
    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        // XOR the input block with the IV or previous ciphertext block
        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            mode_ctx->mode_state.cbc_internal.iv[j] ^= in[i + j];
        }
        
        // Encrypt the block using the block cipher
        if (mode_ctx->cipher_ctx->cipher_api->cipher_process(
                mode_ctx->cipher_ctx, mode_ctx->mode_state.cbc_internal.iv, out + i, dir) != BLOCK_CIPHER_OK) {
            fprintf(stderr, "Error processing block in CBC mode\n");
            return;
        }
        
        // Update the IV to the current ciphertext block
        memcpy(mode_ctx->mode_state.cbc_internal.iv, out + i, BLOCK_SIZE);
    }
}

void cbc_dispose(ModeOfOperationContext *mode_ctx) {
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