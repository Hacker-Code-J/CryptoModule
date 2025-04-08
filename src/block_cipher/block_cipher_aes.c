/*
 * Copyright 2002-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * rijndael-alg-fst.c
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen
 * @author Antoon Bosselaers
 * @author Paulo Barreto
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* File: src/block_cipher/block_cipher_aes.c */
#include "../../include/block_cipher/block_cipher_aes.h"

/* Forward declarations of static functions. */
static int  aes_init(BlockCipherContext *ctx, size_t block_size, const u8 *key, size_t key_len);
static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct);
static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt);
static void aes_dispose(BlockCipherContext *ctx);

/* The global vtable for AES. */

/**
 * @brief The AES block cipher API.
 * @details This structure contains function pointers to the AES encryption and decryption functions,
 *          as well as the initialization and disposal functions.
 *          The AES algorithm is a symmetric key block cipher that operates on 128-bit blocks of data
 *          using keys of 128, 192, or 256 bits.
 *          The AES algorithm is widely used in various applications, including secure communications,
 *          data encryption, and file protection.
 *          The AES API provides a simple interface for initializing the cipher, encrypting and decrypting data,
 *          and disposing of the cipher context.
 *          The AES algorithm is based on a substitution-permutation network (SPN) structure,
 *          which consists of a series of rounds that involve substitution, permutation, and mixing operations.
 *          The number of rounds depends on the key length:
 *          - AES-128: 10 rounds
 *          - AES-192: 12 rounds
 *          - AES-256: 14 rounds
 *          The AES API provides a consistent interface for different key lengths,
 *          allowing users to choose the desired key length based on their security requirements.
 *          The AES API is designed to be easy to use and efficient, making it suitable for a wide range of applications.
 */
static const BlockCipherApi AES_API = {
    .name          = "AES",
    .init          = aes_init,
    .encrypt_block = aes_encrypt,
    .decrypt_block = aes_decrypt,
    .dispose       = aes_dispose
};

/* Public function declared in block_cipher_aes.h */
const BlockCipherApi* get_aes_api(void) { return &AES_API; }

/**
 * @brief The internal structure for AES encryption.
 * @details This structure contains the state of the AES algorithm, including the round keys and the number of rounds.
 *          The round keys are derived from the original key using the key expansion algorithm.
 *          The number of rounds depends on the key length:
 *          - AES-128: 10 rounds
 *          - AES-192: 12 rounds
 *          - AES-256: 14 rounds
 */
typedef struct AesInternal {
    size_t block_size;  /* Typically must be 16 for AES */
    size_t key_len;     /* 16, 24, or 32 for AES-128/192/256 */
    u32 round_keys[60]; 
    /*
     *    The round keys are derived from the original key using the key expansion algorithm.
     *    The number of round keys depends on the key length:
     *    - AES-128: 10 rounds, 11 round keys
     *    - AES-192: 12 rounds, 13 round keys
     *    - AES-256: 14 rounds, 15 round keys           T
     *    The round keys are stored in an array of 32-bit words.
     *    The size of the array is 4 * (number of rounds + 1).
     *    For example, for AES-128, the size is 4 * (10 + 1) = 44 words.
     *    For AES-192, the size is 4 * (12 + 1) = 52 words.
     *    For AES-256, the size is 4 * (14 + 1) = 60 words.
    */
    int nr;             /* e.g., 10 for AES-128, 12, or 14... */
} AesInternal;

/* Forward declarations of static functions. */
int aes_enc_key_expansion(AesInternal* st, const u8* in, u32* out);   //  AES Encryption Key Expansion
// static int aes_dec_key_expansion(AesInternal* st, const u8* in, u8* out);   //  AES Decryption Key Expansion

/* ********** AES key expansion functions ********** */
int aes_enc_key_expansion(AesInternal* st, const u8* in, u32* out) {
    if (!st || !in || !out) return -1;
    if (st->key_len != 16 && st->key_len != 24 && st->key_len != 32) return -1;  /* unsupported key length */

    u32 temp;
    int i, n;

    for (i = 0; i < st->key_len / 4; i++) {
        out[i] = GETU32(in + (i * 4));
    }

    n = st->key_len / 4;
    for (i = n; i < ((n + 6) + 1) * 4; i++) {
        temp = out[i - 1];
        if (i % n == 0) {
            temp = sub_word(rotate_word(temp)) ^ rcon[i / n - 1];
        } else if ((n > 6) && (i % n == 4)) {
            temp = sub_word(temp);
        }
        out[i] = out[i - n] ^ temp;
    }

    // for (i = 0; i < st->key_len; i++) {
    //     printf("%08x:", out[i]);
    //     if (i % 4 == 3) printf("\n");
    // }

    return -1;
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
    // for (size_t i = 0; i < st->block_size; i++) {
    //     ct[i] = pt[i] ^ 0xAA;
    // }

    const u32* rk;
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    int r;

    rk = st->round_keys; 
    r = st->nr;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(pt     ) ^ rk[0];
    s1 = GETU32(pt +  4) ^ rk[1];
    s2 = GETU32(pt +  8) ^ rk[2];
    s3 = GETU32(pt + 12) ^ rk[3];

    /* round 1: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
    /* round 2: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
    /* round 3: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
    /* round 4: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
    /* round 5: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
    /* round 6: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
    /* round 7: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
    /* round 8: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
    /* round 9: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
    if (r > 10) {
        /* round 10: */
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
        /* round 11: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
        if (r > 12) {
            /* round 12: */
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
            /* round 13: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
        }
    }
    rk += r << 2;

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
        (Te2[(t0 >> 24)       ] & 0xff000000) ^
        (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
        (Te1[(t3      ) & 0xff] & 0x000000ff) ^
        rk[0];
    PUTU32(ct     , s0);
    s1 =
        (Te2[(t1 >> 24)       ] & 0xff000000) ^
        (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
        (Te1[(t0      ) & 0xff] & 0x000000ff) ^
        rk[1];
    PUTU32(ct +  4, s1);
    s2 =
        (Te2[(t2 >> 24)       ] & 0xff000000) ^
        (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
        (Te1[(t1      ) & 0xff] & 0x000000ff) ^
        rk[2];
    PUTU32(ct +  8, s2);
    s3 =
        (Te2[(t3 >> 24)       ] & 0xff000000) ^
        (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
        (Te1[(t2      ) & 0xff] & 0x000000ff) ^
        rk[3];
    PUTU32(ct + 12, s3);
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
