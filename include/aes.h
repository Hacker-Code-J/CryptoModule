/* File: include/aes.h */
/*
 * Copyright 2002-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "config.h"
#include "mode.h"

#ifndef AES_H
#define AES_H

/**
 * @file aes.h
 * @brief Header file for AES block cipher API.
 * 
 * This file defines the AES block cipher API, including initialization,
 * encryption/decryption, and disposal functions.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE 16

#define AES_ENCRYPT     1
#define AES_DECRYPT     0

#define AES_MAXNR 14

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
    u32 rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;

int AES_set_encrypt_key(const u8 *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const u8 *userKey, const int bits, AES_KEY *key);

void AES_encrypt(const u8 *in, u8 *out, const AES_KEY *key);
void AES_decrypt(const u8 *in, u8 *out, const AES_KEY *key); 

// void aes_block(const u8 *in, u8 *out, const void *key) {
//     const AES_KEY *key = (const AES_KEY*)key;
//     AES_encrypt(in, out, key);
// }

// void aes_ctr(const u8 *in, u8 *out, size_t len, 
//             const void *key, u8 ivec[16], 
//             u8 ecount_buf[16], u32 *num) {
//     AES_ctr128_encrypt(in, out, len,
//                        (const AES_KEY*)key,
//                        ivec, ecount_buf, num);
// }

#ifdef __cplusplus
}
#endif

 #endif // AES_H 