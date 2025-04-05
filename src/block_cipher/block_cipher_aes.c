/* File: src/block_cipher/block_cipher_aes.c */

#include "../../include/block_cipher/block_cipher_aes.h"
#include <string.h> /* for memset, etc. */

/* Forward declares of local (static) functions. */
static int  aes_init    (BlockCipherContext *ctx, const uint8_t *key, size_t key_len);
static void aes_encrypt (BlockCipherContext *ctx, const uint8_t *pt, uint8_t *ct);
static void aes_decrypt (BlockCipherContext *ctx, const uint8_t *ct, uint8_t *pt);
static void aes_dispose (BlockCipherContext *ctx);

/* The global vtable for AES. */
static const BlockCipherApi AES_API = {
    .name          = "AES",
    .block_size    = 16,
    .key_size      = 16,   /* For AES-128 example */
    .init          = aes_init,
    .encrypt_block = aes_encrypt,
    .decrypt_block = aes_decrypt,
    .dispose       = aes_dispose
};

/* Public function declared in block_cipher_aes.h */
const BlockCipherApi* get_aes_api(void)
{
    return &AES_API;
}

/* The struct we store in ctx->internal_data for AES. */
typedef struct AesInternal {
    uint8_t round_keys[176]; /* example 176 for AES-128 key schedule */
    int nr;                  /* number of rounds, e.g. 10 for AES-128 */
} AesInternal;

/* ********** Function Definitions ********** */

static int aes_init(BlockCipherContext *ctx, const uint8_t *key, size_t key_len)
{
    if (!ctx || !key) return -1;
    if (key_len != 16) return -1;

    /* Link the context to the vtable, just in case. */
    ctx->api = &AES_API;

    /* Zero out the internal data. */
    AesInternal *st = (AesInternal *) ctx->internal_data;
    memset(st, 0, sizeof(*st));

    /* Fake "key expansion" */
    st->nr = 10; /* AES-128 rounds */
    /* Normally you'd do a real key schedule. We'll just do a placeholder. */
    memcpy(st->round_keys, key, 16);

    return 0;
}

static void aes_encrypt(BlockCipherContext *ctx, const uint8_t *pt, uint8_t *ct)
{
    if (!ctx || !pt || !ct) return;
    AesInternal *st = (AesInternal *) ctx->internal_data;

    /* Placeholder: just do a naive copy to show structure. */
    /* In real code, you'd do AES block encryption using st->round_keys. */
    for (int i = 0; i < 16; i++) {
        ct[i] = pt[i] ^ 0xAA; /* trivial XOR for example only */
    }
}

static void aes_decrypt(BlockCipherContext *ctx, const uint8_t *ct, uint8_t *pt)
{
    if (!ctx || !ct || !pt) return;
    AesInternal *st = (AesInternal *) ctx->internal_data;

    /* Reverse the trivial XOR for example. */
    for (int i = 0; i < 16; i++) {
        pt[i] = ct[i] ^ 0xAA;
    }
}

static void aes_dispose(BlockCipherContext *ctx)
{
    if (!ctx) return;
    AesInternal *st = (AesInternal *) ctx->internal_data;
    /* Zeroize memory. */
    memset(st, 0, sizeof(*st));
}


// #include "../../include/blockcipher/block_cipher_aes.h"
// #include <string.h>  // for memcpy, etc.

// /* Internally used structure to hold AES round keys, state, etc. */
// typedef struct AesInternal {
//     uint8_t round_keys[240]; // max for AES-256
//     int nr;                  // number of rounds
//     // ...
// } AesInternal;

// /* Forward declarations of static functions. */
// static int  aes_init(BlockCipherContext *ctx, const uint8_t *key, size_t key_len);
// static void aes_encrypt(BlockCipherContext *ctx, const uint8_t *pt, uint8_t *ct);
// static void aes_decrypt(BlockCipherContext *ctx, const uint8_t *ct, uint8_t *pt);
// static void aes_dispose(BlockCipherContext *ctx);

// /* The vtable for AES. */
// static const BlockCipherApi AES_API = {
//     .name          = "AES",
//     .block_size    = 16,
//     .key_size      = 16,  /* we might only do AES-128 for this example */
//     .init          = aes_init,
//     .encrypt_block = aes_encrypt,
//     .decrypt_block = aes_decrypt,
//     .dispose       = aes_dispose
// };

// const BlockCipherApi *get_aes_api(void)
// {
//     return &AES_API;
// }

// static int aes_init(BlockCipherContext *ctx, const uint8_t *key, size_t key_len)
// {
//     if (!ctx || !key) return -1;
//     if (key_len != 16) return -1; // For AES-128 example

//     /* Save pointer to the vtable, just in case it's not set yet. */
//     ctx->api = &AES_API;

//     /* The internal_data can be interpreted as our AesInternal. */
//     AesInternal *st = (AesInternal *) ctx->internal_data;
//     memset(st, 0, sizeof(*st));

//     // ... perform key expansion, fill st->round_keys, st->nr etc. ...
//     // For brevity, not shown here.

//     return 0; // success
// }

// static void aes_encrypt(BlockCipherContext *ctx, const uint8_t *pt, uint8_t *ct)
// {
//     // if (!ctx || !pt || !ct) return;
//     // AesInternal *st = (AesInternal *)ctx->internal_data;

//     // ... do block encryption using st->round_keys ...
// }

// static void aes_decrypt(BlockCipherContext *ctx, const uint8_t *ct, uint8_t *pt)
// {
//     // if (!ctx || !ct || !pt) return;
//     // AesInternal *st = (AesInternal *)ctx->internal_data;

//     // ... do block decryption ...
// }

// static void aes_dispose(BlockCipherContext *ctx)
// {
//     if (!ctx) return;
//     AesInternal *st = (AesInternal *)ctx->internal_data;
//     memset(st, 0, sizeof(*st)); // zeroize round keys
// }
