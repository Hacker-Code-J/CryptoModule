/* File: include/block_cipher/block_cipher.h */

#include "../api.h"

#ifndef BLOCK_CIPHER_H
#define BLOCK_CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

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
  *          The BlockCipherApi structure is used to provide a consistent interface for different block ciphers,
  *          allowing users to easily switch between different ciphers without changing the code that uses them.
  *          The structure is designed to be extensible, allowing for the addition of new ciphers in the future.
  */
typedef struct __BlockCipherApi__ {
    const char *name; /* e.g. "AES" or "MyCipher" */

    /**
     * @brief Initialize the block cipher context.
     * @param ctx Pointer to the context to be initialized.
     * @param block_size Size of the block (e.g., 16 for AES).
     * @param key Pointer to the key.
     * @param key_len Length of the key in bytes.
     * @return 0 on success, non-zero on failure.
     */
    int (*init)(BlockCipherContext* ctx, size_t block_size, const u8* key, size_t key_len);

    /* Encrypt exactly one block. */

    /**
     * @brief Encrypt a block of plaintext.
     * @param ctx Pointer to the context.
     * @param pt Pointer to the plaintext block to be encrypted.
     * @param ct Pointer to the buffer where the ciphertext will be stored.
     */
    void (*encrypt_block)(BlockCipherContext* ctx, const u8* pt, u8* ct);

    /**
     * @brief Decrypt exactly one block.
     * @param ctx Pointer to the context.
     * @param ct Pointer to the ciphertext block to be decrypted.
     * @param pt Pointer to the buffer where the plaintext will be stored.
     */
    void (*decrypt_block)(BlockCipherContext* ctx, const u8* ct, u8* pt);

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
 *          The structure is designed to be extensible, allowing for the addition of new ciphers in the future.
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