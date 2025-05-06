/* File: include/mode/mode_api */
#include "../api_cryptomodule.h"
#include "../block_cipher/api_block_cipher.h"
#include "../block_cipher/block_cipher_aes.h"
#include "../block_cipher/block_cipher_aria.h"
#include "../block_cipher/block_cipher_lea.h"

#ifndef MODE_API_H
#define MODE_API_H

#ifdef __cplusplus
extern "C" {
#endif

#define GCM_BLOCK_LEN   16  // Standard GCM block length
#define GCM_IV_LEN      12  // Standard GCM IV length


// Enumeration for supported block cipher modes
typedef enum {
    MODE_ECB = 0xECB,
    MODE_CBC = 0xCBC,
    MODE_CTR = 0xC12,
    MODE_GCM = 0xFC1,
    MODE_UNKNOWN = 0x000
} ModeOfOperationType;

static inline const char* mode_type_to_string(ModeOfOperationType mode) {
    switch (mode) {
        case MODE_ECB: return "ECB";
        case MODE_CBC: return "CBC";
        case MODE_CTR: return "CTR";
        case MODE_GCM: return "GCM";
        default: return "Unknown Mode";
    }
}

typedef struct __ModeOfOperationContext__ ModeOfOperationContext;

typedef struct __ModeOfOperationApi__ {
    const char *mode_name; /* e.g. "ECB", "CBC", "CTR", "GCM" */

    /**
     * @brief Initialize the mode context with block cipher + parameters.
     */
    void (*mode_init)(
        ModeOfOperationContext *mode_ctx,
        const u8 *key, size_t key_len,
        const u8 *iv, size_t iv_len,
        u8 *in, size_t in_len,
        BlockCipherDirection dir);

    void (*mode_process)(
        ModeOfOperationContext *mode_ctx,
        const u8 *in, u8 *out, size_t padded_len,
        BlockCipherDirection dir);

    void (*mode_process_with_tag)(
        ModeOfOperationContext *mode_ctx,
        const u8 *in, u8 *out, size_t pt_len,
        const u8 *aad, size_t aad_len,
        const u8 *tag, size_t tag_len,
        BlockCipherDirection dir);

    /**
     * @brief Clean up resources.
     */
    void (*mode_dispose)(ModeOfOperationContext *mode_ctx);
} ModeOfOperationApi;

typedef struct __ModeInternal__ {
    /* CBC Mode State */
    struct __cbc_internal__ { 
        // Note: The IV is not used in the encryption process, but it is needed for decryption. 
        u8 iv[BLOCK_SIZE];   // Current IV (for CBC chaining).
    } cbc_internal;

    /* CTR Mode State */
    struct __ctr_internal__ {
        // Note: The IV is not used in the encryption process, but it is needed for decryption.
        u8 counter[BLOCK_SIZE];   // Current counter
    } ctr_internal;

    /* GCM Mode State (Authenticated Encryption with Associated Data) */
    struct __gcm_internal__ {
        // Note: The IV is not used in the encryption process, but it is needed for decryption.
        u8 iv[GCM_IV_LEN];       // J0 = IV || 0x00 || 0x00 || 0x00 || 0x00
        u8 H[GCM_BLOCK_LEN];    // H = AES(0x00) (ghash key)
        u8 *ghash_table;        // Flat 2560x16 lookup table for ghash
    } gcm_internal;

    /* ECB Mode State */
    struct __ecb_internal__ {
        // Note: ECB does not require any internal state.
        // This is a placeholder for future use or extensions.
        int dummy;  // Placeholder for future use
    } ecb_internal;

} ModeInternal;

struct __ModeOfOperationContext__ {
    ModeOfOperationType mode_type; // Type of the mode (e.g., ECB, CBC, CTR, GCM)
    const ModeOfOperationApi *mode_api;  // Pointer to the mode API
    BlockCipherType cipher_type; // Type of the block cipher (e.g., AES, ARIA, LEA)
    BlockCipherContext *cipher_ctx;      // Pointer to the block cipher context
    ModeInternal mode_state;            // Internal state for the mode of operation
};

// static inline void clear_mode_ctx(ModeOfOperationContext *ctx) {
//     if (ctx) memset(ctx, 0, sizeof(*ctx));
// }

const ModeOfOperationApi *mode_factory(const char *name);

void print_mode_internal(const ModeOfOperationContext* ctx, const char* mode_type);

/**
 * @brief Pad the input buffer using PKCS#7 padding.
 * @param buf Pointer to the buffer to be padded.
 * @param data_len Length of the data in the buffer.
 * @param block_size Block size for padding (e.g., 16 bytes for AES).
 * @return Length of the padded buffer.
 * @details This function adds PKCS#7 padding to the input buffer. The padding consists of bytes
 *          with the value of the number of padding bytes added. For example, if 5 bytes of padding
 *          are added, the last 5 bytes of the buffer will be 0x05.
 *          The function returns the total length of the padded buffer.
 */
size_t pkcs7_pad(u8 *buf, size_t data_len, size_t block_size);

/**
 * @brief Unpad the input buffer using PKCS#7 padding.
 * @param buf Pointer to the buffer to be unpadded.
 * @param buf_len Length of the padded buffer.
 * @param block_size Block size for unpadding (e.g., 16 bytes for AES).
 * @return Length of the unpadded buffer.
 * @details This function removes PKCS#7 padding from the input buffer. It checks the last byte
 *          of the buffer to determine how many bytes to remove. The function returns the length
 *          of the unpadded buffer.
 */
size_t pkcs7_unpad(u8 *buf, size_t buf_len, size_t block_size);

/**
 * @brief Pad the input buffer using ANSI X9.23 padding.
 * @param buf Pointer to the buffer to be padded.
 * @param data_len Length of the data in the buffer.
 * @param block_size Block size for padding (e.g., 16 bytes for AES).
 * @return Length of the padded buffer.
 * @details This function adds ANSI X9.23 padding to the input buffer. The padding consists of
 *          a single byte with the value of the number of padding bytes added, followed by
 *          zero bytes. For example, if 5 bytes of padding are added, the last byte will be 0x05
 *          and the preceding 4 bytes will be 0x00.
 */
size_t ansi923_pad(u8 *buf, size_t data_len, size_t block_size);

/**
 * @brief Unpad the input buffer using ANSI X9.23 padding.
 * @param buf Pointer to the buffer to be unpadded.
 * @param buf_len Length of the padded buffer.
 * @param block_size Block size for unpadding (e.g., 16 bytes for AES).
 * @return Length of the unpadded buffer.
 * @details This function removes ANSI X9.23 padding from the input buffer. It checks the last byte
 *          of the buffer to determine how many bytes to remove. The function returns the length
 *          of the unpadded buffer.
 */
size_t ansi923_unpad(u8 *buf, size_t buf_len, size_t block_size);

/**
 * @brief Pad the input buffer using ISO/IEC 7816-4 padding.
 * @param buf Pointer to the buffer to be padded.
 * @param data_len Length of the data in the buffer.
 * @param block_size Block size for padding (e.g., 16 bytes for AES).
 * @return Length of the padded buffer.
 * @details This function adds ISO/IEC 7816-4 padding to the input buffer. The padding consists of
 *          a single byte with the value 0x80, followed by zero bytes until the end of the block.
 */
size_t iso7816_4_pad(u8 *buf, size_t data_len, size_t block_size);

/**
 * @brief Unpad the input buffer using ISO/IEC 7816-4 padding.
 * @param buf Pointer to the buffer to be unpadded.
 * @param buf_len Length of the padded buffer.
 * @param block_size Block size for unpadding (e.g., 16 bytes for AES).
 * @return Length of the unpadded buffer.
 * @details This function removes ISO/IEC 7816-4 padding from the input buffer. It checks the last byte
 *          of the buffer to determine how many bytes to remove. The function returns the length
 *          of the unpadded buffer.
 */
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