/* File: src/mode/ecb.c */
#include "../../include/mode/mode_api.h"

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