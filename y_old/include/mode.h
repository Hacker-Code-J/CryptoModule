/* File: include/mode.h */
/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "config.h"
#include "mem.h"

#ifndef MODE_H
#define MODE_H

/**
 * @file mode.h
 * @brief Header file for mode of operation APIs.
 */


# define U64(C) C##ULL

#define STRICT_ALIGNMENT 1
#ifndef PEDANTIC
# if defined(__i386)    || defined(__i386__)    || \
     defined(__x86_64)  || defined(__x86_64__)  || \
     defined(_M_IX86)   || defined(_M_AMD64)    || defined(_M_X64) || \
     defined(__aarch64__)                       || \
     defined(__s390__)  || defined(__s390x__)
#  undef STRICT_ALIGNMENT
# endif
#endif

#if defined(_MSC_VER)
  #include <stdlib.h>
  #define BSWAP8(x)  _byteswap_uint64(x)
  #define BSWAP4(x)  _byteswap_ulong  (x)
#elif defined(__GNUC__) || defined(__clang__)
  /* these are in GCC/Clang even on non-x86 */
  #define BSWAP8(x)  __builtin_bswap64(x)
  #define BSWAP4(x)  __builtin_bswap32(x)
#else
  /* Portable fallback */
  static inline uint64_t BSWAP8(uint64_t x) {
      return ((x & 0x00000000000000FFULL) << 56) |
             ((x & 0x000000000000FF00ULL) << 40) |
             ((x & 0x0000000000FF0000ULL) << 24) |
             ((x & 0x00000000FF000000ULL) << 8)  |
             ((x & 0x000000FF00000000ULL) >> 8)  |
             ((x & 0x0000FF0000000000ULL) >> 24) |
             ((x & 0x00FF000000000000ULL) >> 40) |
             ((x & 0xFF00000000000000ULL) >> 56);
  }
  static inline uint32_t BSWAP4(uint32_t x) {
      return ((x & 0x000000FFU) << 24) |
             ((x & 0x0000FF00U) << 8)  |
             ((x & 0x00FF0000U) >> 8)  |
             ((x & 0xFF000000U) >> 24);
  }
#endif

#if defined(BSWAP4) && !defined(STRICT_ALIGNMENT)
# define GETU32(p)       BSWAP4(*(const u32 *)(p))
# define PUTU32(p,v)     *(u32 *)(p) = BSWAP4(v)
#else
# define GETU32(p)       ((u32)(p)[0]<<24|(u32)(p)[1]<<16|(u32)(p)[2]<<8|(u32)(p)[3])
# define PUTU32(p,v)     ((p)[0]=(u8)((v)>>24),(p)[1]=(u8)((v)>>16),(p)[2]=(u8)((v)>>8),(p)[3]=(u8)(v))
#endif

/*- GCM definitions */ typedef struct {
    u64 hi, lo;
} u128;

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*block128_f) (const u8 in[16],
                            u8 out[16], const void *key);

typedef void (*cbc128_f) (const u8 *in, u8 *out,
                          size_t len, const void *key,
                          u8 ivec[16], int enc);

typedef void (*ctr128_f) (const u8 *in, u8 *out,
                          size_t blocks, const void *key,
                          const u8 ivec[16]);

void CRYPTO_cbc128_encrypt(const u8 *in, u8 *out,
                           size_t len, const void *key,
                           u8 ivec[16], block128_f block);
void CRYPTO_cbc128_decrypt(const u8 *in, u8 *out,
                           size_t len, const void *key,
                           u8 ivec[16], block128_f block);

void CRYPTO_ctr128_encrypt(const u8 *in, u8 *out,
                           size_t len, const void *key,
                           u8 ivec[16],
                           u8 ecount_buf[16], unsigned int *num,
                           block128_f block);
void CRYPTO_ctr128_encrypt_ctr32(const u8 *in, u8 *out,
                                 size_t len, const void *key,
                                 u8 ivec[16],
                                 u8 ecount_buf[16],
                                 unsigned int *num, ctr128_f func);

void gcm_init_4bit(u128 Htable[16], const u64 H[2]);
void gcm_gmult_4bit(u64 Xi[2], const u128 Htable[16]);                  
void gcm_ghash_4bit(u64 Xi[2], const u128 Htable[16], const u8 *inp, size_t len);

typedef void (*gcm_init_fn)(u128 Htable[16], const u64 H[2]);
typedef void (*gcm_ghash_fn)(u64 Xi[2], const u128 Htable[16], const u8 *inp, size_t len);
typedef void (*gcm_gmult_fn)(u64 Xi[2], const u128 Htable[16]);
struct gcm_funcs_st {
    gcm_init_fn ginit;
    gcm_ghash_fn ghash;
    gcm_gmult_fn gmult;
};

struct gcm128_context {
    /* Following 6 names follow names in GCM specification */
    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Relative position of Yi, EKi, EK0, len, Xi, H and pre-computed Htable is
     * used in some assembler modules, i.e. don't change the order!
     */
    u128 Htable[16];
    struct gcm_funcs_st funcs;
    u32 mres, ares;
    block128_f block;
    void *key;
};

typedef struct gcm128_context GCM128_CONTEXT;

GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block);
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block);
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const u8 *iv, size_t len);
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const u8 *aad, size_t len);
int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx, const u8 *in, u8 *out, size_t len);
int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx, const u8 *in, u8 *out, size_t len);
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx, const u8 *in, u8 *out, size_t len, ctr128_f stream);
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx, const u8 *in, u8 *out, size_t len, ctr128_f stream);
int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, const u8 *tag, size_t len);
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, u8 *tag, size_t len);
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);

#ifdef __cplusplus
}
#endif

#endif // MODE_H