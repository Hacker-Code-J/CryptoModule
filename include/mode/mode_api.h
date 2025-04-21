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
} ModeOfOperationType;

static inline const char* mode_to_string(ModeOfOperationType mode) {
    switch (mode) {
        case MODE_ECB: return "ECB";
        case MODE_CBC: return "CBC";
        case MODE_CTR: return "CTR";
        default: return "Unknown Mode";
    }
}

typedef struct __ModeOfOperationContext__ ModeOfOperationContext;

typedef struct __ModeOfOperationApi__ {
    const char *name;

    /**
     * @brief Initialize the mode context with block cipher + parameters.
     */
    void (*init)(ModeOfOperationContext *ctx,
                const BlockCipherApi *cipher_api,
                const u8 *key,
                size_t key_len,
                const u8 *iv,
                size_t iv_len,
                BlockCipherDirection dir);

    /**
     * @brief Process data in place (or into a destination buffer).
     * Must handle full-block multiples.
     */
    void (*process)(ModeOfOperationContext *ctx,
                    const u8 *in,
                    u8 *out,
                    size_t len,
                    BlockCipherDirection dir);

    /**
     * @brief Clean up resources.
     */
    void (*dispose)(ModeOfOperationContext *ctx);
} ModeOfOperationApi;

typedef union __ModeInternal__ {
    struct __cbc_internal__ {
        u8 iv[BLOCK_SIZE];         // Initial Vector
        u8 prev_block[BLOCK_SIZE]; // Previous ciphertext (CBC chaining)
    } cbc_internal;
    struct __ctr_internal__ {
        u8 counter[BLOCK_SIZE];
        u8 keystream_block[BLOCK_SIZE];
        u32 block_index;
    } ctr_internal;
    struct __gcm_internal__ {
        // GCM internal fields
        u8 iv[BLOCK_SIZE];
        u64 auth_len;
        u64 cipher_len;
        u8 tag[BLOCK_SIZE];
        // etc.
    } gcm_internal;
    struct __ecb_internal__ {
        // ECB has no internal state
        char dummy;
    } ecb_internal;

} ModeInternal;

struct __ModeOfOperationContext__ {
    const ModeOfOperationApi *api;  // Pointer to the mode API
    BlockCipherContext cipher_ctx; // Block cipher context
    ModeInternal internal_data;     // Internal state for the mode
};

// typedef enum {
//     BLOCK_CIPHER_MODE_OK = 0,
//     BLOCK_CIPHER_MODE_ERR_INVALID_INPUT,
//     BLOCK_CIPHER_MODE_ERR_UNSUPPORTED_MODE,
// } block_cipher_mode_status_t;

// // Context structure for block cipher mode operations
// typedef struct {
//     BlockCipherMode mode;
//     BlockCipherContext *cipher_context; // Pointer to the block cipher context
//     u8 iv[16];       // Initialization vector (for CBC and CTR modes)
//     size_t iv_size;       // Size of the IV
//     u8 counter[16];  // Counter (for CTR mode)
// } BlockCipherModeContext;

// // Function to initialize the mode context
// block_cipher_mode_status_t mode_init(BlockCipherModeContext* ctx, BlockCipherMode mode, BlockCipherContext* cipher_context, const u8* iv, size_t iv_size);

// // Function to encrypt data using the specified mode
// block_cipher_mode_status_t mode_encrypt(BlockCipherModeContext* ctx, const u8* input, u8* output, size_t length);

// // Function to decrypt data using the specified mode
// block_cipher_mode_status_t mode_decrypt(BlockCipherModeContext* ctx, const u8* input, u8* output, size_t length);

// // Function to reset the mode context (e.g., for reusing the context with a new IV)
// block_cipher_mode_status_t mode_reset(BlockCipherModeContext* ctx, const u8* iv, size_t iv_size);

#ifdef __cplusplus
}
#endif

#endif /* MODE_API_H */