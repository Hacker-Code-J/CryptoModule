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

/**
 * @brief Block cipher direction enumeration.
 * @details This enumeration defines the direction of the block cipher operation.
 */
typedef enum {
    BLOCK_CIPHER_ENCRYPTION = 0xE, // Encryption mode
    BLOCK_CIPHER_DECRYPTION = 0xD  // Decryption mode
} BlockCipherDirection;

// /**
//  * @brief Block cipher type enumeration.
//  * @details This enumeration defines the types of block ciphers supported.
//  */
// typedef enum {
//     BLOCK_CIPHER_AES = 0x0A,  // A for AES
//     BLOCK_CIPHER_ARIA = 0x0B, // B for ARIA
//     BLOCK_CIPHER_LEA = 0x0C,  // C for LEA
//     BLOCK_CIPHER_UNKNOWN = 0x00 // Default unknown type
// } BlockCipherType;

/**
 * @brief Block cipher status enumeration.
 * @details This enumeration defines the status codes for block cipher operations.
 */
typedef enum {
    BLOCK_CIPHER_OK                     = 0x00,
    BLOCK_CIPHER_OK_INITIALIZATION      = 0x01,
    BLOCK_CIPHER_OK_KEY_EXPANSION       = 0x02,
    BLOCK_CIPHER_OK_ENCRYPTION          = 0x03,
    BLOCK_CIPHER_OK_DECRYPTION          = 0x04,
    BLOCK_CIPHER_OK_PROCESS             = 0x05,
    BLOCK_CIPHER_OK_DISPOSE             = 0x06,
    BLOCK_CIPHER_ERR_AES_API            = 0x10,
    BLOCK_CIPHER_ERR_ARIA_API           = 0x11,
    BLOCK_CIPHER_ERR_LEA_API            = 0x12,
    BLOCK_CIPHER_ERR_INVALID_DIRECTION  = 0x1D,  // Direction error
    BLOCK_CIPHER_ERR_INITIALIZATION     = 0x2A,  // Initialization error
    BLOCK_CIPHER_ERR_KEY_EXPANSION      = 0x2B,  // Key expansion error
    BLOCK_CIPHER_ERR_ENCRYPTION         = 0x2C,  // Encryption error
    BLOCK_CIPHER_ERR_DECRYPTION         = 0x2D,  // Decryption error
    BLOCK_CIPHER_ERR_DISPOSE            = 0x2E,  // Dispose error
    BLOCK_CIPHER_ERR_INVALID_KEY_SIZE   = 0x30,
    BLOCK_CIPHER_ERR_INVALID_BLOCK_SIZE = 0x31,
    BLOCK_CIPHER_ERR_INVALID_INPUT      = 0x32,
    BLOCK_CIPHER_ERR_INVALID_OUTPUT     = 0x33,
    BLOCK_CIPHER_ERR_INVALID_MODE       = 0x34,
    BLOCK_CIPHER_ERR_MEMORY_ALLOCATION  = 0x40,
    // BLOCK_CIPHER_ERR_UNSUPPORTED_ALGORITHM,
    // BLOCK_CIPHER_ERR_MEMORY_ALLOCATION,
} block_cipher_status_t;

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
     * @param block_size Size of the block (e.g., 16 for AES).
     * @param key Pointer to the key.
     * @param key_len Length of the key in bytes.
     * @param dir Direction of the cipher (ENCRYPTION_MODE or DECRYPTION_MODE).
     * @return Status of the initialization (BLOCK_CIPHER_OK or error code).
     */
    block_cipher_status_t (*init)(BlockCipherContext* ctx, const u8* key, size_t key_len, size_t block_size, BlockCipherDirection dir);

    /**
     * @brief Process a block of data (encrypt or decrypt).
     * @param ctx Pointer to the context.
     * @param in Pointer to the input block (plaintext for encryption, ciphertext for decryption).
     * @param out Pointer to the buffer where the output will be stored (ciphertext for encryption, plaintext for decryption).
     * @param dir Direction of the cipher (ENCRYPTION_MODE or DECRYPTION_MODE).
     * @return Status of the operation (BLOCK_CIPHER_OK or error code).
     */
    block_cipher_status_t (*process_block)(BlockCipherContext* ctx, const u8* in, u8* out, BlockCipherDirection dir);

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
        u32 round_keys[60];     /* max for AES-256 */
        int nr;                 /* e.g., 10 for AES-128, 12, or 14... */
    } aes_internal;
    struct __aria_internal__ {
        size_t block_size;      /* Typically must be 16 for ARIA */
        size_t key_len;         /* 16, 24, or 32 for ARIA-128/192/256 */
        u32 round_keys[68];     /* max for ARIA-256 */
        int nr;                 /* e.g., 12 for ARIA-128, 14, or 16... */
    } aria_internal;
    struct __lea_internal__ {
        size_t block_size;      /* Typically must be 16 for LEA */
        size_t key_len;         /* 16, 24, or 32 for LEA-128/192/256 */
        u32 round_keys[128];    /* max for LEA-256 */
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
    const BlockCipherApi* api;  
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
const BlockCipherApi* block_cipher_factory(const char *name);

/**
 * @brief Factory function to create a block cipher API.
 * @param name Name of the cipher (e.g., "AES").
 * @return Pointer to the BlockCipherApi structure for the specified cipher, or NULL if not found.
 * @details This function is used to create a block cipher API based on the specified name.
 *          It allows for dynamic selection of the cipher at runtime, making it easier to switch between
 *          different ciphers without changing the code that uses them.
 */
void print_cipher_internal(const BlockCipherContext* ctx, const char* cipher_type);

/* For usage:
 *   BlockCipherContext ctx;
 *   ctx.api = &AES_API; // or ARIA_API, LEA_API, etc.
 *   ctx.internal_data.aes_internal.block_size = 16; // for AES
 *   ctx.internal_data.aes_internal.key_len = 16; // for AES-128
 *   ...
 */

#ifdef __cplusplus
}
#endif

#endif /* BLOCK_CIPHER_H */


// typedef enum {
//     BLOCK_CIPHER_INIT,
//     BLOCK_CIPHER_ENCRYPT,
//     BLOCK_CIPHER_DECRYPT,
//     BLOCK_CIPHER_DISPOSE
// } BlockCipherOperation;
// typedef enum {
//     BLOCK_CIPHER_SUCCESS = 0,
//     BLOCK_CIPHER_FAILURE = -1
// } BlockCipherResult;
// typedef enum {
//     BLOCK_CIPHER_UNINITIALIZED = 0,
//     BLOCK_CIPHER_INITIALIZED,
//     BLOCK_CIPHER_ENCRYPTING,
//     BLOCK_CIPHER_DECRYPTING,
//     BLOCK_CIPHER_DISPOSED
// } BlockCipherState;