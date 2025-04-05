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
typedef struct BlockCipherApi {
    const char *name; /* e.g. "AES" or "MyCipher" */

    /*
     * Initialize the cipher with the chosen block size and key.
     * If the algorithm only supports certain block sizes (e.g., 16 bytes) 
     * or certain key lengths, it can reject others with a return code.
     */
    int (*init)(
        BlockCipherContext* ctx,
        size_t block_size,
        const u8* key,
        size_t key_len
    );

    /* Encrypt exactly one block. */
    void (*encrypt_block)(
        BlockCipherContext* ctx,
        const u8* plaintext,
        u8* ciphertext
    );

    /* Decrypt exactly one block. */
    void (*decrypt_block)(
        BlockCipherContext* ctx,
        const u8* ciphertext,
        u8* plaintext
    );

    /* Clean up resources, if needed. */
    void (*dispose)(
        BlockCipherContext* ctx
    );

} BlockCipherApi;

/* 
 * The context object holds internal state. Different ciphers may store differently.
 * The first field must be a pointer to the vtable for the chosen cipher.
 */
/* The context structure storing state. */
struct BlockCipherContext {
    const BlockCipherApi *api;  
    u8 internal_data[256]; /* Example placeholder for key schedule, etc. */
};

/* For usage:
   1) Acquire a pointer to a specific BlockCipherApi (AES, ARIA, LEA).
   2) Create a BlockCipherContext and call api->init(...).
   3) Then call encrypt_block/decrypt_block as needed.
   4) Finally call dispose(...) if the cipher requires cleanup.
*/

#ifdef __cplusplus
}
#endif

#endif /* BLOCK_CIPHER_H */