/* File: include/mode/mode_api */
#include "../cryptomodule_api.h"
#include "../block_cipher/block_cipher_api.h"
#include "../block_cipher/block_cipher_aes.h"
#include "../block_cipher/block_cipher_aria.h"
#include "../block_cipher/block_cipher_lea.h"
// #include "../cryptomodule_utils.h"
// #include "../cryptomodule_test.h"


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
    const char *mode_name; /* e.g. "ECB", "CBC", "CTR" */

    /**
     * @brief Initialize the mode context with block cipher + parameters.
     */
    void (*mode_init)(
        ModeOfOperationContext *mode_ctx,
        BlockCipherType cipher_type,
        const u8 *key,
        size_t key_len,
        const u8 *iv,
        size_t iv_len,
        u8 *in,
        size_t in_len,
        BlockCipherDirection dir);

    /**
     * @brief Process data in place (or into a destination buffer).
     * Must handle full-block multiples.
     */
    void (*mode_update)(
        ModeOfOperationContext *mode_ctx,
        const u8 *in, size_t in_len,
        u8 *out, size_t out_len,
        BlockCipherDirection dir);

    void (*mode_update_auth)(
        ModeOfOperationContext *mode_ctx,
        const u8 *in,
        size_t in_len,
        BlockCipherDirection dir);

    void (*mode_finalize)(
        ModeOfOperationContext *mode_ctx,
        const u8 *in,
        u8 *out,
        size_t in_len,
        size_t out_len,
        BlockCipherDirection dir);

    void (*mode_finalize_auth)(
        ModeOfOperationContext *mode_ctx,
        const u8 *in,
        size_t in_len,
        BlockCipherDirection dir);

    /**
     * @brief Clean up resources.
     */
    void (*mode_dispose)(ModeOfOperationContext *mode_ctx);
} ModeOfOperationApi;

typedef struct __ModeInternal__ {
    /* CBC Mode State */
    struct __cbc_internal__ { 
        u8 iv[BLOCK_SIZE];   // Current IV (for CBC chaining). 
    } cbc_internal;

    /* CTR Mode State */
    struct __ctr_internal__ {
        u8 counter[BLOCK_SIZE];   // Current counter
        u8 keystream[BLOCK_SIZE]; // Keystream bytes (encrypted counter) not yet used.
        size_t keystream_used;    // How many bytes of the keystream buffer have been used (next byte index for XOR).
        // Note: keystream is generated on the fly, so we don't need to store the whole keystream.
    } ctr_internal;

    /* GCM Mode State (Authenticated Encryption with Associated Data) */
    struct __gcm_internal__ {
        u8 J0[BLOCK_SIZE];        // Initial block for CTR mode (J0 = IV || 0^96).
        u8 counter[BLOCK_SIZE];   // Current counter for CTR (starts from J0 incremented as per GCM spec).
        u8 keystream[BLOCK_SIZE]; // Keystream for CTR mode (like in standard CTR).
        size_t keystream_used;    // Bytes of keystream used so far from current counter block.
        u8 H[BLOCK_SIZE];        // Hash subkey H = E(K, 0^block_size) for GHASH (GCM authentication).
        u8 ghash_state[BLOCK_SIZE]; // GHASH accumulator (X) for computing authentication tag.
        u64 aad_length;          // Total length of AAD processed (in bytes).
        u64 data_length;         // Total length of plaintext/ciphertext processed (in bytes).
        u8 aad_buffer[BLOCK_SIZE];  // Buffer for partial AAD block (if AAD length is not a multiple of 16).
        size_t aad_buf_len;         // Current bytes in aad_buffer.
        u8 data_buffer[BLOCK_SIZE]; // Buffer for partial data block for GHASH (if data_length not multiple of 16).
        size_t data_buf_len;        // Current bytes in data_buffer.
        // Note: The following fields are commented out as they are not used in the current implementation.
    } gcm_internal;

    /* ECB Mode State */
    struct __ecb_internal__ {
        // ECB mode does not require any internal state.
        // This is just a placeholder to maintain the structure.
        char dummy;  // (unused, just to ensure the union has a distinct member)
    } ecb_internal;

} ModeInternal;

struct __ModeOfOperationContext__ {
    const ModeOfOperationApi *mode_api;  // Pointer to the mode API
    BlockCipherContext *cipher_ctx;      // Pointer to the block cipher context
    ModeInternal mode_internal_data; // Internal state for the mode of operation
    size_t block_size; // Block size in bytes
    u8 buffer[BLOCK_SIZE]; // Buffer for partial blocks
    size_t buffer_len; // Length of the buffered data
    size_t total_len; // Total length of data processed
    // Note: The internal_data union contains state for different modes (CBC, CTR, GCM, ECB).
    // The specific mode in use will determine which part of the union is relevant.
};

static inline void clear_mode_ctx(ModeOfOperationContext *ctx) {
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

const ModeOfOperationApi *mode_factory(const char *name);

void print_mode_internal(const ModeOfOperationContext* ctx, const char* mode_type);

// void pkcs7_pad(u8 *data, size_t data_len, size_t block_size);

size_t pkcs7_pad(u8 *buf, size_t data_len, size_t block_size);
size_t pkcs7_unpad(u8 *buf, size_t buf_len, size_t block_size);
size_t ansi923_pad(u8 *buf, size_t data_len, size_t block_size);
size_t ansi923_unpad(u8 *buf, size_t buf_len, size_t block_size);
size_t iso7816_4_pad(u8 *buf, size_t data_len, size_t block_size);
size_t iso7816_4_unpad(u8 *buf, size_t buf_len, size_t block_size);

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