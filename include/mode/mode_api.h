/* File: include/mode/mode_api */
#include "../cryptomodule_api.h"
#include "../block_cipher/block_cipher_api.h"
#include "../block_cipher/block_cipher_aes.h"
#include "../block_cipher/block_cipher_aria.h"
#include "../block_cipher/block_cipher_lea.h"
#include "../cryptomodule_utils.h"
#include "../cryptomodule_test.h"


#ifndef MODE_API_H
#define MODE_API_H

#ifdef __cplusplus
extern "C" {
#endif

// Enumeration for supported block cipher modes
typedef enum {
    MODE_ECB,
    MODE_CBC,
    MODE_CTR
} BlockCipherMode;

typedef enum {
    BLOCK_CIPHER_MODE_OK = 0,
    BLOCK_CIPHER_MODE_ERR_INVALID_INPUT,
    BLOCK_CIPHER_MODE_ERR_UNSUPPORTED_MODE,
} block_cipher_mode_status_t;

// Context structure for block cipher mode operations
typedef struct {
    BlockCipherMode mode;
    BlockCipherContext *cipher_context; // Pointer to the block cipher context
    u8 iv[16];       // Initialization vector (for CBC and CTR modes)
    size_t iv_size;       // Size of the IV
    u8 counter[16];  // Counter (for CTR mode)
} BlockCipherModeContext;

// Function to initialize the mode context
block_cipher_mode_status_t mode_init(BlockCipherModeContext* ctx, BlockCipherMode mode, BlockCipherContext* cipher_context, const u8* iv, size_t iv_size);

// Function to encrypt data using the specified mode
block_cipher_mode_status_t mode_encrypt(BlockCipherModeContext* ctx, const u8* input, u8* output, size_t length);

// Function to decrypt data using the specified mode
block_cipher_mode_status_t mode_decrypt(BlockCipherModeContext* ctx, const u8* input, u8* output, size_t length);

// Function to reset the mode context (e.g., for reusing the context with a new IV)
block_cipher_mode_status_t mode_reset(BlockCipherModeContext* ctx, const u8* iv, size_t iv_size);

#ifdef __cplusplus
}
#endif

#endif /* MODE_API_H */