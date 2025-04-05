/* File: include/block_cipher/block_cipher.h */
#ifndef BLOCK_CIPHER_H
#define BLOCK_CIPHER_H

#include <stddef.h>
#include <stdint.h>

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
    const char *name;           /* e.g. "AES" */
    size_t      block_size;     /* typically 16 for AES */
    size_t      key_size;       /* e.g. 16 for AES-128, or dynamic */

    /* Initialize the cipher context with a key. */
    int  (*init)(BlockCipherContext *ctx, const uint8_t *key, size_t key_len);

    /* Encrypt exactly one block. */
    void (*encrypt_block)(BlockCipherContext *ctx,
                          const uint8_t *plaintext,
                          uint8_t *ciphertext);

    /* Decrypt exactly one block. */
    void (*decrypt_block)(BlockCipherContext *ctx,
                          const uint8_t *ciphertext,
                          uint8_t *plaintext);

    /* Clean up resources, if needed. */
    void (*dispose)(BlockCipherContext *ctx);

} BlockCipherApi;

/* The context structure storing state. */
struct BlockCipherContext {
    const BlockCipherApi *api;  
    uint8_t internal_data[256]; /* Example placeholder for key schedule, etc. */
};

#ifdef __cplusplus
}
#endif

#endif /* BLOCK_CIPHER_H */



// const BlockCipherApi *aes_api = get_aes_api();

// /* Forward declaration for a block cipher context (private). */
// typedef struct BlockCipherContext BlockCipherContext;

// /* The function pointer table describing any block cipher. */
// typedef struct BlockCipherApi {
//     const char *name;
//     size_t      block_size;
//     size_t      key_size;

//     /* Initialize the cipher context with a given key (and maybe rounds, etc.). */
//     int  (*init)(BlockCipherContext *ctx, const uint8_t *key, size_t key_len);

//     /* Encrypt exactly one block (in-place or out-of-place). */
//     void (*encrypt_block)(BlockCipherContext *ctx,
//                           const uint8_t *plaintext,
//                           uint8_t *ciphertext);

//     /* Decrypt exactly one block. */
//     void (*decrypt_block)(BlockCipherContext *ctx,
//                           const uint8_t *ciphertext,
//                           uint8_t *plaintext);

//     /* Cleanup or free resources if needed. */
//     void (*dispose)(BlockCipherContext *ctx);
// } BlockCipherApi;

// /* The context object holds internal state. Different ciphers may store differently. */
// struct BlockCipherContext {
//     const BlockCipherApi *api;  /* points to the vtable for the chosen cipher */
//     /* followed by cipher-specific fields */
//     uint8_t internal_data[256]; /* Example placeholder for storing S-boxes, round keys, etc. */
// };

// /* For usage:
//    1) Acquire a pointer to a specific BlockCipherApi (AES, ARIA, LEA).
//    2) Create a BlockCipherContext and call api->init(...).
//    3) Then call encrypt_block/decrypt_block as needed.
//    4) Finally call dispose(...) if the cipher requires cleanup.
// */

// #ifdef __cplusplus
// }
// #endif

// #endif /* BLOCK_CIPHER_H */
