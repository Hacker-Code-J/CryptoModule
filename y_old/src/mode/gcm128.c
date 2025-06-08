/*
 * Copyright 2010-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "mode.h"

#define GCM_MUL(ctx)      ctx->funcs.gmult(ctx->Xi.u,ctx->Htable)
/*
 * GHASH_CHUNK is "stride parameter" missioned to mitigate cache trashing
 * effect. In other words idea is to hash data while it's still in L1 cache
 * after encryption pass...
 */
#  define GHASH_CHUNK       (3*1024)

#if defined(__GNUC__) && !defined(STRICT_ALIGNMENT)
typedef size_t size_t_aX __attribute((__aligned__(1)));
#else
typedef size_t size_t_aX;
#endif

static void gcm_get_funcs(struct gcm_funcs_st *ctx)
{
    /* set defaults -- overridden below as needed */
    ctx->ginit = gcm_init_4bit;
    ctx->gmult = gcm_gmult_4bit;
    ctx->ghash = gcm_ghash_4bit;
}

/*-
 *
 * NOTE: TABLE_BITS and all non-4bit implementations have been removed in 3.1.
 *
 * Even though permitted values for TABLE_BITS are 8, 4 and 1, it should
 * never be set to 8. 8 is effectively reserved for testing purposes.
 * TABLE_BITS>1 are lookup-table-driven implementations referred to as
 * "Shoup's" in GCM specification. In other words OpenSSL does not cover
 * whole spectrum of possible table driven implementations. Why? In
 * non-"Shoup's" case memory access pattern is segmented in such manner,
 * that it's trivial to see that cache timing information can reveal
 * fair portion of intermediate hash value. Given that ciphertext is
 * always available to attacker, it's possible for him to attempt to
 * deduce secret parameter H and if successful, tamper with messages
 * [which is nothing but trivial in CTR mode]. In "Shoup's" case it's
 * not as trivial, but there is no reason to believe that it's resistant
 * to cache-timing attack. And the thing about "8-bit" implementation is
 * that it consumes 16 (sixteen) times more memory, 4KB per individual
 * key + 1KB shared. Well, on pros side it should be twice as fast as
 * "4-bit" version. And for gcc-generated x86[_64] code, "8-bit" version
 * was observed to run ~75% faster, closer to 100% for commercial
 * compilers... Yet "4-bit" procedure is preferred, because it's
 * believed to provide better security-performance balance and adequate
 * all-round performance. "All-round" refers to things like:
 *
 * - shorter setup time effectively improves overall timing for
 *   handling short messages;
 * - larger table allocation can become unbearable because of VM
 *   subsystem penalties (for example on Windows large enough free
 *   results in VM working set trimming, meaning that consequent
 *   malloc would immediately incur working set expansion);
 * - larger table has larger cache footprint, which can affect
 *   performance of other code paths (not necessarily even from same
 *   thread in Hyper-Threading world);
 *
 * Value of 1 is not appropriate for performance reasons.
 */
#define REDUCE1BIT(V)   do { \
        if (sizeof(size_t)==8) { \
                u64 T = U64(0xe100000000000000) & (0-(V.lo&1)); \
                V.lo  = (V.hi<<63)|(V.lo>>1); \
                V.hi  = (V.hi>>1 )^T; \
        } \
        else { \
                u32 T = 0xe1000000U & (0-(u32)(V.lo&1)); \
                V.lo  = (V.hi<<63)|(V.lo>>1); \
                V.hi  = (V.hi>>1 )^((u64)T<<32); \
        } \
} while(0)
void gcm_init_4bit(u128 Htable[16], const u64 H[2]) {
    u128 V;
    Htable[0].hi = 0;
    Htable[0].lo = 0;
    V.hi = H[0];
    V.lo = H[1];
    Htable[8] = V;
    REDUCE1BIT(V);
    Htable[4] = V;
    REDUCE1BIT(V);
    Htable[2] = V;
    REDUCE1BIT(V);
    Htable[1] = V;
    Htable[3].hi = V.hi ^ Htable[2].hi, Htable[3].lo = V.lo ^ Htable[2].lo;
    V = Htable[4];
    Htable[5].hi = V.hi ^ Htable[1].hi, Htable[5].lo = V.lo ^ Htable[1].lo;
    Htable[6].hi = V.hi ^ Htable[2].hi, Htable[6].lo = V.lo ^ Htable[2].lo;
    Htable[7].hi = V.hi ^ Htable[3].hi, Htable[7].lo = V.lo ^ Htable[3].lo;
    V = Htable[8];
    Htable[9].hi = V.hi ^ Htable[1].hi, Htable[9].lo = V.lo ^ Htable[1].lo;
    Htable[10].hi = V.hi ^ Htable[2].hi, Htable[10].lo = V.lo ^ Htable[2].lo;
    Htable[11].hi = V.hi ^ Htable[3].hi, Htable[11].lo = V.lo ^ Htable[3].lo;
    Htable[12].hi = V.hi ^ Htable[4].hi, Htable[12].lo = V.lo ^ Htable[4].lo;
    Htable[13].hi = V.hi ^ Htable[5].hi, Htable[13].lo = V.lo ^ Htable[5].lo;
    Htable[14].hi = V.hi ^ Htable[6].hi, Htable[14].lo = V.lo ^ Htable[6].lo;
    Htable[15].hi = V.hi ^ Htable[7].hi, Htable[15].lo = V.lo ^ Htable[7].lo;
}

#define PACK(s)         ((size_t)(s)<<(sizeof(size_t)*8-16))
static const size_t rem_4bit[16] = {
    PACK(0x0000), PACK(0x1C20), PACK(0x3840), PACK(0x2460),
    PACK(0x7080), PACK(0x6CA0), PACK(0x48C0), PACK(0x54E0),
    PACK(0xE100), PACK(0xFD20), PACK(0xD940), PACK(0xC560),
    PACK(0x9180), PACK(0x8DA0), PACK(0xA9C0), PACK(0xB5E0)
};
void gcm_gmult_4bit(u64 Xi[2], const u128 Htable[16]) {
    u128 Z;
    int cnt = 15;
    size_t rem, nlo, nhi;

    nlo = ((const u8 *)Xi)[15];
    nhi = nlo >> 4;
    nlo &= 0xf;

    Z.hi = Htable[nlo].hi;
    Z.lo = Htable[nlo].lo;

    while (1) {
        rem = (size_t)Z.lo & 0xf;
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if (sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (u64)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nhi].hi;
        Z.lo ^= Htable[nhi].lo;

        if (--cnt < 0)
            break;

        nlo = ((const u8 *)Xi)[cnt];
        nhi = nlo >> 4;
        nlo &= 0xf;

        rem = (size_t)Z.lo & 0xf;
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if (sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (u64)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nlo].hi;
        Z.lo ^= Htable[nlo].lo;
    }

#  ifdef BSWAP8
    Xi[0] = BSWAP8(Z.hi);
    Xi[1] = BSWAP8(Z.lo);
#  else
    u8 *p = (u8 *)Xi;
    u32 v;
    v = (u32)(Z.hi >> 32);
    PUTU32(p, v);
    v = (u32)(Z.hi);
    PUTU32(p + 4, v);
    v = (u32)(Z.lo >> 32);
    PUTU32(p + 8, v);
    v = (u32)(Z.lo);
    PUTU32(p + 12, v);
#  endif
}
/*
 * Streamed gcm_mult_4bit, see CRYPTO_gcm128_[en|de]crypt for
 * details... Compiler-generated code doesn't seem to give any
 * performance improvement, at least not on x86[_64]. It's here
 * mostly as reference and a placeholder for possible future
 * non-trivial optimization[s]...
 */
void gcm_ghash_4bit(u64 Xi[2], const u128 Htable[16],
                           const u8 *inp, size_t len) {
    u128 Z;
    int cnt;
    size_t rem, nlo, nhi;
    do {
        cnt = 15;
        nlo = ((const u8 *)Xi)[15];
        nlo ^= inp[15];
        nhi = nlo >> 4;
        nlo &= 0xf;

        Z.hi = Htable[nlo].hi;
        Z.lo = Htable[nlo].lo;

        while (1) {
            rem = (size_t)Z.lo & 0xf;
            Z.lo = (Z.hi << 60) | (Z.lo >> 4);
            Z.hi = (Z.hi >> 4);
            if (sizeof(size_t) == 8)
                Z.hi ^= rem_4bit[rem];
            else
                Z.hi ^= (u64)rem_4bit[rem] << 32;

            Z.hi ^= Htable[nhi].hi;
            Z.lo ^= Htable[nhi].lo;

            if (--cnt < 0)
                break;

            nlo = ((const u8 *)Xi)[cnt];
            nlo ^= inp[cnt];
            nhi = nlo >> 4;
            nlo &= 0xf;

            rem = (size_t)Z.lo & 0xf;
            Z.lo = (Z.hi << 60) | (Z.lo >> 4);
            Z.hi = (Z.hi >> 4);
            if (sizeof(size_t) == 8)
                Z.hi ^= rem_4bit[rem];
            else
                Z.hi ^= (u64)rem_4bit[rem] << 32;

            Z.hi ^= Htable[nlo].hi;
            Z.lo ^= Htable[nlo].lo;
        }


#   ifdef BSWAP8
        Xi[0] = BSWAP8(Z.hi);
        Xi[1] = BSWAP8(Z.lo);
#   else
        u8 *p = (u8 *)Xi;
        u32 v;
        v = (u32)(Z.hi >> 32);
        PUTU32(p, v);
        v = (u32)(Z.hi);
        PUTU32(p + 4, v);
        v = (u32)(Z.lo >> 32);
        PUTU32(p + 8, v);
        v = (u32)(Z.lo);
        PUTU32(p + 12, v);
#   endif

        inp += 16;
        /* Block size is 128 bits so len is a multiple of 16 */
        len -= 16;
    } while (len > 0);
}

void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->key = key;

    (*block) (ctx->H.c, ctx->H.c, key);

    /* H is stored in host byte order */
#ifdef BSWAP8
    ctx->H.u[0] = BSWAP8(ctx->H.u[0]);
    ctx->H.u[1] = BSWAP8(ctx->H.u[1]);
#else
    u8 *p = ctx->H.c;
    u64 hi, lo;
    hi = (u64)GETU32(p) << 32 | GETU32(p + 4);
    lo = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
    ctx->H.u[0] = hi;
    ctx->H.u[1] = lo;
#endif

    gcm_get_funcs(&ctx->funcs);
    ctx->funcs.ginit(ctx->Htable, ctx->H.u);
}

void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const u8 *iv, size_t len) {
    u32 ctr;

    ctx->len.u[0] = 0;          /* AAD length */
    ctx->len.u[1] = 0;          /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    if (len == 12) {
        memcpy(ctx->Yi.c, iv, 12);
        ctx->Yi.c[12] = 0;
        ctx->Yi.c[13] = 0;
        ctx->Yi.c[14] = 0;
        ctx->Yi.c[15] = 1;
        ctr = 1;
    } else {
        size_t i;
        u64 len0 = len;

        /* Borrow ctx->Xi to calculate initial Yi */
        ctx->Xi.u[0] = 0;
        ctx->Xi.u[1] = 0;

        while (len >= 16) {
            for (i = 0; i < 16; ++i)
                ctx->Xi.c[i] ^= iv[i];
            GCM_MUL(ctx);
            iv += 16;
            len -= 16;
        }
        if (len) {
            for (i = 0; i < len; ++i)
                ctx->Xi.c[i] ^= iv[i];
            GCM_MUL(ctx);
        }
        len0 <<= 3;
#ifdef BSWAP8
        ctx->Xi.u[1] ^= BSWAP8(len0);
#else
        ctx->Xi.c[8] ^= (u8)(len0 >> 56);
        ctx->Xi.c[9] ^= (u8)(len0 >> 48);
        ctx->Xi.c[10] ^= (u8)(len0 >> 40);
        ctx->Xi.c[11] ^= (u8)(len0 >> 32);
        ctx->Xi.c[12] ^= (u8)(len0 >> 24);
        ctx->Xi.c[13] ^= (u8)(len0 >> 16);
        ctx->Xi.c[14] ^= (u8)(len0 >> 8);
        ctx->Xi.c[15] ^= (u8)(len0);
#endif
        GCM_MUL(ctx);

#ifdef BSWAP4
        ctr = BSWAP4(ctx->Xi.d[3]);
#else
        ctr = GETU32(ctx->Xi.c + 12);
#endif

        /* Copy borrowed Xi to Yi */
        ctx->Yi.u[0] = ctx->Xi.u[0];
        ctx->Yi.u[1] = ctx->Xi.u[1];
    }

    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;

    (*ctx->block) (ctx->Yi.c, ctx->EK0.c, ctx->key);
    ++ctr;
#ifdef BSWAP4
    ctx->Yi.d[3] = BSWAP4(ctr);
#else
    PUTU32(ctx->Yi.c + 12, ctr);
#endif
}

int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const u8 *aad, size_t len) {
    size_t i;
    unsigned int n;
    u64 alen = ctx->len.u[0];

    if (ctx->len.u[1])
        return -2;

    alen += len;
    if (alen > (U64(1) << 61) || (sizeof(len) == 8 && alen < len))
        return -1;
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if (n) {
        while (n && len) {
            ctx->Xi.c[n] ^= *(aad++);
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0)
            GCM_MUL(ctx);
        else {
            ctx->ares = n;
            return 0;
        }
    }
    while (len >= 16) {
        for (i = 0; i < 16; ++i)
            ctx->Xi.c[i] ^= aad[i];
        GCM_MUL(ctx);
        aad += 16;
        len -= 16;
    }
    if (len) {
        n = (unsigned int)len;
        for (i = 0; i < len; ++i)
            ctx->Xi.c[i] ^= aad[i];
    }

    ctx->ares = n;
    return 0;
}

int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx, const u8 *in, u8 *out, size_t len) {
    u32 n, ctr, mres;
    size_t i;
    u64 mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if (ctx->ares) {
        GCM_MUL(ctx);
        ctx->ares = 0;
    }

#ifdef BSWAP4
    ctr = BSWAP4(ctx->Yi.d[3]);
#else
    ctr = GETU32(ctx->Yi.c + 12);
#endif

    n = mres % 16;
    if (16 % sizeof(size_t) == 0) { /* always true actually */
        do {
            if (n) {
                while (n && len) {
                    ctx->Xi.c[n] ^= *(out++) = *(in++) ^ ctx->EKi.c[n];
                    --len;
                    n = (n + 1) % 16;
                }
                if (n == 0) {
                    GCM_MUL(ctx);
                    mres = 0;
                } else {
                    ctx->mres = n;
                    return 0;
                }
            }
# if defined(STRICT_ALIGNMENT)
            if (((size_t)in | (size_t)out) % sizeof(size_t) != 0)
                break;
# endif
            while (len >= 16) {
                size_t *out_t = (size_t *)out;
                const size_t *in_t = (const size_t *)in;

                (*block) (ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
#  ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
#  else
                PUTU32(ctx->Yi.c + 12, ctr);
#  endif
                for (i = 0; i < 16 / sizeof(size_t); ++i)
                    ctx->Xi.t[i] ^= out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                GCM_MUL(ctx);
                out += 16;
                in += 16;
                len -= 16;
            }
            if (len) {
                (*block) (ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
# ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
# else
                PUTU32(ctx->Yi.c + 12, ctr);
# endif
                while (len--) {
                    ctx->Xi.c[n] ^= out[n] = in[n] ^ ctx->EKi.c[n];
                    ++n;
                }
                mres = n;
            }

            ctx->mres = mres;
            return 0;
        } while (0);
    }

    for (i = 0; i < len; ++i) {
        if (n == 0) {
            (*block) (ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
#ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
#else
            PUTU32(ctx->Yi.c + 12, ctr);
#endif
        }

        ctx->Xi.c[n] ^= out[i] = in[i] ^ ctx->EKi.c[n];
        mres = n = (n + 1) % 16;
        if (n == 0)
            GCM_MUL(ctx);
    }

    ctx->mres = mres;
    return 0;
}

int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx, const u8 *in, u8 *out, size_t len) {
    u32 n, ctr, mres;
    size_t i;
    u64 mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void *key = ctx->key;

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if (ctx->ares) {
        /* First call to decrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx);
        ctx->ares = 0;
    }

#ifdef BSWAP4
    ctr = BSWAP4(ctx->Yi.d[3]);
#else
    ctr = GETU32(ctx->Yi.c + 12);
#endif

    n = mres % 16;
    if (16 % sizeof(size_t) == 0) { /* always true actually */
        do {
            if (n) {
                while (n && len) {
                    u8 c = *(in++);
                    *(out++) = c ^ ctx->EKi.c[n];
                    ctx->Xi.c[n] ^= c;
                    --len;
                    n = (n + 1) % 16;
                }
                if (n == 0) {
                    GCM_MUL(ctx);
                    mres = 0;
                } else {
                    ctx->mres = n;
                    return 0;
                }
            }
# if defined(STRICT_ALIGNMENT)
            if (((size_t)in | (size_t)out) % sizeof(size_t) != 0)
                break;
# endif
            while (len >= 16) {
                size_t *out_t = (size_t *)out;
                const size_t *in_t = (const size_t *)in;

                (*block) (ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
#  ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
#  else
                PUTU32(ctx->Yi.c + 12, ctr);
#  endif
                for (i = 0; i < 16 / sizeof(size_t); ++i) {
                    size_t c = in_t[i];
                    out_t[i] = c ^ ctx->EKi.t[i];
                    ctx->Xi.t[i] ^= c;
                }
                GCM_MUL(ctx);
                out += 16;
                in += 16;
                len -= 16;
            }
            if (len) {
                (*block) (ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
# ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
# else
                PUTU32(ctx->Yi.c + 12, ctr);
# endif
                while (len--) {
                    u8 c = in[n];
                    ctx->Xi.c[n] ^= c;
                    out[n] = c ^ ctx->EKi.c[n];
                    ++n;
                }
                mres = n;
            }

            ctx->mres = mres;
            return 0;
        } while (0);
    }

    for (i = 0; i < len; ++i) {
        u8 c;
        if (n == 0) {
            (*block) (ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
#ifdef BSWAP4
            ctx->Yi.d[3] = BSWAP4(ctr);
#else
            PUTU32(ctx->Yi.c + 12, ctr);
#endif
        }

        c = in[i];
        out[i] = c ^ ctx->EKi.c[n];
        ctx->Xi.c[n] ^= c;
        mres = n = (n + 1) % 16;
        if (n == 0)
            GCM_MUL(ctx);
    }

    ctx->mres = mres;
    return 0;
}

int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx, const u8 *in, u8 *out, size_t len, ctr128_f stream) {
    u32 n, ctr, mres;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if (ctx->ares) {
        /* First call to encrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx);
        ctx->ares = 0;
    }

# ifdef BSWAP4
    ctr = BSWAP4(ctx->Yi.d[3]);
# else
    ctr = GETU32(ctx->Yi.c + 12);
# endif

    n = mres % 16;
    if (n) {
        while (n && len) {
            ctx->Xi.c[n] ^= *(out++) = *(in++) ^ ctx->EKi.c[n];
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0) {
            GCM_MUL(ctx);
            mres = 0;
        } else {
            ctx->mres = n;
            return 0;
        }
    }

    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

        (*stream) (in, out, j, key, ctx->Yi.c);
        ctr += (unsigned int)j;
# ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
# else
        PUTU32(ctx->Yi.c + 12, ctr);
# endif
        in += i;
        len -= i;
# if defined(GHASH)
        GHASH(ctx, out, i);
        out += i;
# else
        while (j--) {
            for (i = 0; i < 16; ++i)
                ctx->Xi.c[i] ^= out[i];
            GCM_MUL(ctx);
            out += 16;
        }
# endif
    }
    if (len) {
        (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
        ++ctr;
# ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
# else
        PUTU32(ctx->Yi.c + 12, ctr);
# endif
        while (len--) {
            ctx->Xi.c[mres++] ^= out[n] = in[n] ^ ctx->EKi.c[n];
            ++n;
        }
    }

    ctx->mres = mres;
    return 0;
}

int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx, const u8 *in, u8 *out, size_t len, ctr128_f stream) {
    u32 n, ctr, mres;
    size_t i;
    u64 mlen = ctx->len.u[1];
    void *key = ctx->key;

    mlen += len;
    if (mlen > ((U64(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if (ctx->ares) {
        /* First call to decrypt finalizes GHASH(AAD) */
        GCM_MUL(ctx);
        ctx->ares = 0;
    }

# ifdef BSWAP4
    ctr = BSWAP4(ctx->Yi.d[3]);
# else
    ctr = GETU32(ctx->Yi.c + 12);
# endif

    n = mres % 16;
    if (n) {
        while (n && len) {
            u8 c = *(in++);
            *(out++) = c ^ ctx->EKi.c[n];
            ctx->Xi.c[n] ^= c;
            --len;
            n = (n + 1) % 16;
        }
        if (n == 0) {
            GCM_MUL(ctx);
            mres = 0;
        } else {
            ctx->mres = n;
            return 0;
        }
    }
    if ((i = (len & (size_t)-16))) {
        size_t j = i / 16;

        while (j--) {
            size_t k;
            for (k = 0; k < 16; ++k)
                ctx->Xi.c[k] ^= in[k];
            GCM_MUL(ctx);
            in += 16;
        }
        j = i / 16;
        in -= i;
        
        (*stream) (in, out, j, key, ctx->Yi.c);
        ctr += (unsigned int)j;

# ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
# else
        PUTU32(ctx->Yi.c + 12, ctr);
# endif

        out += i;
        in += i;
        len -= i;
    }
    if (len) {
        (*ctx->block) (ctx->Yi.c, ctx->EKi.c, key);
        ++ctr;
# ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
# else
        PUTU32(ctx->Yi.c + 12, ctr);
# endif
        while (len--) {
            u8 c = in[n];
            ctx->Xi.c[mres++] ^= c;
            out[n] = c ^ ctx->EKi.c[n];
            ++n;
        }
    }

    ctx->mres = mres;
    return 0;
}

int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, const u8 *tag, size_t len) {
    u64 alen = ctx->len.u[0] << 3;
    u64 clen = ctx->len.u[1] << 3;

    if (ctx->mres || ctx->ares)
        GCM_MUL(ctx);
#ifdef BSWAP8
    alen = BSWAP8(alen);
    clen = BSWAP8(clen);
#else
    u8 *p = ctx->len.c;

    ctx->len.u[0] = alen;
    ctx->len.u[1] = clen;

    alen = (u64)GETU32(p) << 32 | GETU32(p + 4);
    clen = (u64)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif

    ctx->Xi.u[0] ^= alen;
    ctx->Xi.u[1] ^= clen;
    GCM_MUL(ctx);

    ctx->Xi.u[0] ^= ctx->EK0.u[0];
    ctx->Xi.u[1] ^= ctx->EK0.u[1];

    if (tag && len <= sizeof(ctx->Xi))
        return CRYPTO_memcmp(ctx->Xi.c, tag, len);
    else
        return -1;
}

void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len)
{
    CRYPTO_gcm128_finish(ctx, NULL, 0);
    memcpy(tag, ctx->Xi.c,
           len <= sizeof(ctx->Xi.c) ? len : sizeof(ctx->Xi.c));
}

GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block) {
    GCM128_CONTEXT *ret;

    if ((ret = malloc(sizeof(*ret))) != NULL)
        CRYPTO_gcm128_init(ret, key, block);

    return ret;
}

void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx) {
    if (ctx == NULL)
        return;
    /* Clear sensitive data */
    memset(ctx->Yi.c, 0, sizeof(ctx->Yi));
    memset(ctx->EKi.c, 0, sizeof(ctx->EKi));
    memset(ctx->EK0.c, 0, sizeof(ctx->EK0));
    memset(ctx->Xi.c, 0, sizeof(ctx->Xi));
    memset(ctx->H.c, 0, sizeof(ctx->H));
    memset(ctx->len.c, 0, sizeof(ctx->len));
    memset(ctx->Htable, 0, sizeof(ctx->Htable));
    ctx->ares = 0;
    ctx->mres = 0;
    ctx->block = NULL;
    ctx->key = NULL;
}