/*
 * Copyright 2002-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* File: src/block_cipher/block_cipher_aes.c */

#include "../../include/block_cipher/block_cipher.h"

/* Forward declarations of static functions. */
static int  aes_init(BlockCipherContext *ctx, size_t block_size, const u8 *key, size_t key_len);
static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct);
static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt);
static void aes_dispose(BlockCipherContext *ctx);

/* The global vtable for AES. */
static const BlockCipherApi AES_API = {
    .name          = "AES",
    .init          = aes_init,
    .encrypt_block = aes_encrypt,
    .decrypt_block = aes_decrypt,
    .dispose       = aes_dispose
};

/* Public function declared in block_cipher_aes.h */
const BlockCipherApi* get_aes_api(void) { return &AES_API; }

/* The type we store in ctx->internal_data. */
typedef struct AesInternal {
    size_t block_size;  /* Typically must be 16 for AES */
    size_t key_len;     /* 16, 24, or 32 for AES-128/192/256 */
    u8 round_keys[240]; /* enough for AES-256 expansions */
    int nr;             /* e.g., 10 for AES-128, 12, or 14... */
} AesInternal;

/* Forward declarations of static functions. */
static int aes_enc_key_expansion(AesInternal* st, const u8* user_key, u8* out);   //  AES Encryption Key Expansion
// static int aes_dec_key_expansion(AesInternal* st, const u8* user_key, u8* out);   //  AES Decryption Key Expansion

/* ********** AES key expansion functions ********** */
/* Rotate a word left by 1 byte */
static inline void rotate_word(u8 w[4]) {
    u8 tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}
/* Sub each byte in a word with the S-box */
static inline void sub_word(u8 w[4]) {
    w[0] = Te4[w[0]];
    w[1] = Te4[w[1]];
    w[2] = Te4[w[2]];
    w[3] = Te4[w[3]];
}

int aes_enc_key_expansion(AesInternal* st, const u8* user_key, u8* out) {
    int i = 0;
    u32 temp;

    out[0] = GETU32(user_key     );
    out[1] = GETU32(user_key +  4);
    out[2] = GETU32(user_key +  8);
    out[3] = GETU32(user_key + 12);
    if (st->key_len == 128) {
        while (1) {
            temp  = out[3];
            out[4] = out[0] ^
                (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te0[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te1[(temp >> 24)       ] & 0x000000ff) ^
                rcon[i];
            out[5] = out[1] ^ out[4];
            out[6] = out[2] ^ out[5];
            out[7] = out[3] ^ out[6];
            if (++i == 10) { return 0; }
            out += 4;
        } // while
    } // if
    out[4] = GETU32(user_key + 16);
    out[5] = GETU32(user_key + 20);
    if (st->key_len == 192) {
        while (1) {
            temp = out[ 5];
            out[ 6] = out[ 0] ^
                (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te0[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te1[(temp >> 24)       ] & 0x000000ff) ^
                rcon[i];
            out[ 7] = out[ 1] ^ out[ 6];
            out[ 8] = out[ 2] ^ out[ 7];
            out[ 9] = out[ 3] ^ out[ 8];
            if (++i == 8) { return 0; }
            out[10] = out[ 4] ^ out[ 9];
            out[11] = out[ 5] ^ out[10];
            out += 6;
        } // while
    } // if
    out[6] = GETU32(user_key + 24);
    out[7] = GETU32(user_key + 28);
    if (st->key_len == 256) {
        while (1) {
            temp = out[ 7];
            out[ 8] = out[ 0] ^
                (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te0[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te1[(temp >> 24)       ] & 0x000000ff) ^
                rcon[i];
            out[ 9] = out[ 1] ^ out[ 8];
            out[10] = out[ 2] ^ out[ 9];
            out[11] = out[ 3] ^ out[10];
            if (++i == 7) { return 0; }
            temp = out[11];
            out[12] = out[ 4] ^
                (Te2[(temp >> 24)       ] & 0xff000000) ^
                (Te3[(temp >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(temp >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(temp      ) & 0xff] & 0x000000ff);
            out[13] = out[ 5] ^ out[12];
            out[14] = out[ 6] ^ out[13];
            out[15] = out[ 7] ^ out[14];
            out += 8;
        }  // while
    } // if

    return -1;
}

void aes128_key_expansion(const u8* user_key, u8* out)
{
    /* Fill out[] with 176 bytes of round keys using the standard algorithm. */
}

void aes192_key_expansion(const u8* user_key, u8* out)
{
    /* Fill out[] with 208 bytes. */
}

void aes256_key_expansion(const u8* user_key, u8* out)
{
    /* Fill out[] with 240 bytes. */
}

/* ********** Implementation of the function pointers ********** */

static int aes_init(BlockCipherContext* ctx,
                    size_t block_size,
                    const u8* key,
                    size_t key_len) {
    if (!ctx || !key) return -1;

    /* AES: block_size must be 16. */
    if (block_size != 16) return -1;  /* unsupported block size for AES */

    /* For AES, key_len can be 16, 24, or 32 bytes. */
    if (key_len != 16 && key_len != 24 && key_len != 32) return -1;  /* unsupported key length */

    /* Link the context to the vtable. */
    ctx->api = &AES_API;
    AesInternal* st = (AesInternal *) ctx->internal_data;
    memset(st, 0, sizeof(*st));

    /* store block_size & key_len for reference. */
    st->block_size = block_size;
    st->key_len    = key_len;

    /* Perform key expansion based on key length. */
    switch (key_len) {
        case 16: st->nr = 10; aes_enc_key_expansion(st, key, st->round_keys); break;
        case 24: st->nr = 12; aes_enc_key_expansion(st, key, st->round_keys); break;
        case 32: st->nr = 14; aes_enc_key_expansion(st, key, st->round_keys); break;
        default: return -1; /* should never happen */
    }

    return 0; /* success */
}

static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct) {
    if (!ctx || !pt || !ct) return;
    AesInternal *st = (AesInternal *)ctx->internal_data;

    /* Real code would do AES encryption. 
    We'll do a trivial mock: XOR with 0xAA for demonstration. */
    for (size_t i = 0; i < st->block_size; i++) {
        ct[i] = pt[i] ^ 0xAA;
    }
}

static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt) {
    if (!ctx || !ct || !pt) return;
    AesInternal *st = (AesInternal *)ctx->internal_data;

    /* trivial mock: XOR with 0xAA again. */
    for (size_t i = 0; i < st->block_size; i++) {
    pt[i] = ct[i] ^ 0xAA;
    }
}

static void aes_dispose(BlockCipherContext *ctx) {
    if (!ctx) return;
    AesInternal *st = (AesInternal *) ctx->internal_data;
    /* zero out everything */
    memset(st, 0, sizeof(*st));
}


// #include "../../include/blockcipher/block_cipher_aes.h"
// #include <string.h>  // for memcpy, etc.

// /* Internally used structure to hold AES round keys, state, etc. */
// typedef struct AesInternal {
//     u8 round_keys[240]; // max for AES-256
//     int nr;                  // number of rounds
//     // ...
// } AesInternal;

// /* Forward declarations of static functions. */
// static int  aes_init(BlockCipherContext *ctx, const u8 *key, size_t key_len);
// static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct);
// static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt);
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

// static int aes_init(BlockCipherContext *ctx, const u8 *key, size_t key_len)
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

// static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct)
// {
//     // if (!ctx || !pt || !ct) return;
//     // AesInternal *st = (AesInternal *)ctx->internal_data;

//     // ... do block encryption using st->round_keys ...
// }

// static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt)
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
