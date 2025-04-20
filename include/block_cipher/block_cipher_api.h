/* File: include/block_cipher/block_cipher.h */
#include "../cryptomodule_api.h"

/**
 * @file block_cipher_api.h
 * @brief This file defines the API for block cipher operations.
 * @details It includes the definitions for block cipher types, key sizes, block sizes,
 *          and the function pointers for initialization, encryption, decryption, and disposal.
 *          The API is designed to be extensible for different block cipher algorithms.
 *          The block cipher API allows for the implementation of various block ciphers
 *          such as AES, ARIA, and LEA. It provides a unified interface for initializing,
 *          processing blocks of data, and disposing of the cipher context.
 *          The API is designed to be extensible for different block cipher algorithms.
 *          The block cipher API allows for the implementation of various block ciphers
 */

#ifndef BLOCK_CIPHER_H
#define BLOCK_CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE      16    /* AES block size in bytes    */
#define AES128_KEY_SIZE     16    /* AES-128 key size in bytes  */
#define AES192_KEY_SIZE     24    /* AES-192 key size in bytes  */
#define AES256_KEY_SIZE     32    /* AES-256 key size in bytes  */
#define AES128_NUM_ROUNDS   10    /* AES-128 number of rounds   */
#define AES192_NUM_ROUNDS   12    /* AES-192 number of rounds   */
#define AES256_NUM_ROUNDS   14    /* AES-256 number of rounds   */

#define ARIA_BLOCK_SIZE     16    /* ARIA block size in bytes   */
#define ARIA128_KEY_SIZE    16    /* ARIA-128 key size in bytes */
#define ARIA192_KEY_SIZE    24    /* ARIA-192 key size in bytes */
#define ARIA256_KEY_SIZE    32    /* ARIA-256 key size in bytes */
#define ARIA128_NUM_ROUNDS  12    /* ARIA-128 number of rounds  */
#define ARIA192_NUM_ROUNDS  14    /* ARIA-192 number of rounds  */
#define ARIA256_NUM_ROUNDS  16    /* ARIA-256 number of rounds  */

#define LEA_BLOCK_SIZE      16    /* LEA block size in bytes    */
#define LEA128_KEY_SIZE     16    /* LEA-128 key size in bytes  */
#define LEA192_KEY_SIZE     24    /* LEA-192 key size in bytes  */
#define LEA256_KEY_SIZE     32    /* LEA-256 key size in bytes  */
#define LEA128_NUM_ROUNDS   24    /* LEA-128 number of rounds   */
#define LEA192_NUM_ROUNDS   28    /* LEA-192 number of rounds   */
#define LEA256_NUM_ROUNDS   32    /* LEA-256 number of rounds   */
typedef enum {
    BLOCK_CIPHER_AES128 = 0xAE5128,   // Identifier for AES-128
    BLOCK_CIPHER_AES192 = 0xAE5192,   // Identifier for AES-192
    BLOCK_CIPHER_AES256 = 0xAE5256,   // Identifier for AES-256
    BLOCK_CIPHER_ARIA128 = 0xA21A128, // Identifier for ARIA-128
    BLOCK_CIPHER_ARIA192 = 0xA21A192, // Identifier for ARIA-192
    BLOCK_CIPHER_ARIA256 = 0xA21A256, // Identifier for ARIA-256
    BLOCK_CIPHER_LEA128 = 0x1EA128,   // Identifier for LEA-128
    BLOCK_CIPHER_LEA192 = 0x1EA192,   // Identifier for LEA-192
    BLOCK_CIPHER_LEA256 = 0x1EA256,   // Identifier for LEA-256
    BLOCK_CIPHER_UNKNOWN = 0x00 // Default unknown type
} BlockCipherType;

/**
 * @brief Converts a BlockCipherType to its corresponding string representation.
 * @param type The BlockCipherType value.
 * @return A string representing the cipher type (e.g., "AES-128", "ARIA-256").
 */
static inline const char *block_cipher_type_to_string(BlockCipherType type) {
    switch (type) {
        case BLOCK_CIPHER_AES128: return "AES-128";
        case BLOCK_CIPHER_AES192: return "AES-192";
        case BLOCK_CIPHER_AES256: return "AES-256";
        case BLOCK_CIPHER_ARIA128: return "ARIA-128";
        case BLOCK_CIPHER_ARIA192: return "ARIA-192";
        case BLOCK_CIPHER_ARIA256: return "ARIA-256";
        case BLOCK_CIPHER_LEA128: return "LEA-128";
        case BLOCK_CIPHER_LEA192: return "LEA-192";
        case BLOCK_CIPHER_LEA256: return "LEA-256";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Block cipher direction enumeration.
 * @details This enumeration defines the direction of the block cipher operation.
 */
typedef enum {
    BLOCK_CIPHER_ENCRYPTION = 0xE, // Encryption mode
    BLOCK_CIPHER_DECRYPTION = 0xD  // Decryption mode
} BlockCipherDirection;

/**
 * @brief Block cipher status enumeration.
 * @details This enumeration defines the status of block cipher operations.
 */
static inline const char *block_cipher_direction_to_string(BlockCipherDirection dir) {
    switch (dir) {
        case BLOCK_CIPHER_ENCRYPTION: return "ENCRYPTION";
        case BLOCK_CIPHER_DECRYPTION: return "DECRYPTION";
        default: return "UNKNOWN";
    }
}

/* Forward declaration for the context. */
typedef struct BlockCipherContext BlockCipherContext;

/* 
 * The vtable or function pointer set describing any block cipher. 
 * We'll name it `BlockCipherApi`.
 */

 /**
  * @brief The BlockCipherApi structure.
  * @details This structure contains function pointers for the block cipher operations.
  *          It includes the cipher name, initialization function, encryption and decryption functions,
  *          and a dispose function for cleaning up the context.
  */
typedef struct __BlockCipherApi__ {
    const char *name; /* e.g. "AES" or "MyCipher" */

    /**
     * @brief Initialize the block cipher context.
     * @param ctx Pointer to the context to be initialized.
     * @param key Pointer to the key.
     * @param key_len Length of the key in bytes.
     * @param block_len Length of the block in bytes.
     * @param dir Direction of the cipher (ENCRYPTION_MODE or DECRYPTION_MODE).
     * @return Status of the initialization (BLOCK_CIPHER_OK or error code).
     */
    void (*init)(BlockCipherContext* ctx, const u8* key, size_t key_len, size_t block_len, BlockCipherDirection dir);

    /**
     * @brief Process a block of data (encrypt or decrypt).
     * @param ctx Pointer to the context.
     * @param in Pointer to the input block (plaintext for encryption, ciphertext for decryption).
     * @param out Pointer to the buffer where the output will be stored (ciphertext for encryption, plaintext for decryption).
     * @param dir Direction of the cipher (ENCRYPTION_MODE or DECRYPTION_MODE).
     * @return Status of the operation (BLOCK_CIPHER_OK or error code).
     */
    void (*process_block)(BlockCipherContext* ctx, const u8* in, u8* out, BlockCipherDirection dir);

    /**
     * @brief Dispose of the block cipher context.
     * @param ctx Pointer to the context to be disposed of.
     * @details This function should clean up any resources allocated for the context.
     *          It may also zero out sensitive data in the context.
     */
    void (*dispose)(BlockCipherContext* ctx);

} BlockCipherApi;

/**
 * @brief The internal structure for block ciphers.
 * @details This structure contains the internal state of the cipher, including round keys and other parameters.
 *          It is used to store the state of the cipher during encryption and decryption operations.
 */
typedef union __CipherInternal__ {
    struct __aes_internal__ {
        size_t block_size;      /* Typically must be 16 for AES */
        size_t key_len;         /* 16, 24, or 32 for AES-128/192/256 */
        /* max 60 for AES-256 */
        u32 round_keys[4 * (AES256_NUM_ROUNDS + 1)];     
        int nr;                 /* e.g., 10 for AES-128, 12, or 14... */
    } aes_internal;
    struct __aria_internal__ {
        size_t block_size;      /* Typically must be 16 for ARIA */
        size_t key_len;         /* 16, 24, or 32 for ARIA-128/192/256 */
        /* max 68 for ARIA-256 */
        u32 round_keys[4 * (ARIA256_NUM_ROUNDS + 1)];     
        int nr;                 /* e.g., 12 for ARIA-128, 14, or 16... */
    } aria_internal;
    struct __lea_internal__ {
        size_t block_size;      /* Typically must be 16 for LEA */
        size_t key_len;         /* 16, 24, or 32 for LEA-128/192/256 */
        /* max 128 for LEA-256 */
        u32 round_keys[4 * (LEA256_NUM_ROUNDS + 1)];    
        int nr;                 /* e.g., 24 for LEA-128, 28, or 32... */
    } lea_internal;
} CipherInternal;

/* 
 * The context object holds internal state. Different ciphers may store differently.
 * The first field must be a pointer to the vtable for the chosen cipher.
 */

/**
 * @brief The BlockCipherContext structure.
 * @details This structure holds the context for a block cipher, including a pointer to the cipher API
 *          and the internal state of the cipher. It is used to manage the state of the cipher during
 *          encryption and decryption operations.
 */
struct BlockCipherContext {
    const BlockCipherApi *api;  
    CipherInternal internal_data; /* Generic internal state for any cipher */
};

static inline void clear_block_cipher_ctx(BlockCipherContext *ctx) {
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

/**
 * @brief Factory function to create a block cipher API.
 * @param name Name of the cipher (e.g., "AES").
 * @return Pointer to the BlockCipherApi structure for the specified cipher, or NULL if not found.
 * @details This function is used to create a block cipher API based on the specified name.
 */
const BlockCipherApi *block_cipher_factory(const char *name);

/**
 * @brief Factory function to create a block cipher API.
 * @param name Name of the cipher (e.g., "AES").
 * @return Pointer to the BlockCipherApi structure for the specified cipher, or NULL if not found.
 * @details This function is used to create a block cipher API based on the specified name.
 *          It allows for dynamic selection of the cipher at runtime, making it easier to switch between
 *          different ciphers without changing the code that uses them.
 */
void print_cipher_internal(const BlockCipherContext* ctx, const char* cipher_type);

#ifdef __cplusplus
}
#endif

#endif /* BLOCK_CIPHER_H */