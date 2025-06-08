#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#include "mode.h"
#include "aes.h"

/* ------------------------------------------------------------------
 * hex2bin(): convert hex string (even length) to binary bytes.
 * Returns 0 on success, -1 on failure (invalid hex or overflow).
 * ------------------------------------------------------------------ */
static int hex2bin(const char *hex, unsigned char *out, size_t outlen) {
    size_t i;
    unsigned int byte;
    if (strlen(hex) != outlen*2) return -1;
    for (i = 0; i < outlen; i++) {
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

int main(void) {
    /* Example 128-bit key, IV and plaintext from NIST SP800-38A §6.5 */
    const u8 key_bytes[16] = {
       0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
       0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    };
    const u8 iv_bytes[16] = {
       0xf0,0xf1,0xf2,0xf3, 0xf4,0xf5,0xf6,0xf7,
       0xf8,0xf9,0xfa,0xfb, 0xfc,0xfd,0xfe,0xff
    };
    const u8 pt[64] = {
       /* 4×16-byte blocks of known plaintext… */
    };
    /* expected CT from the spec… */
    const u8 ct_expected[64] = { /* … */ };

    AES_KEY aes_key;
    u8 ct1[64], ct2[64], ct3[64], ct4[64];
    u8 ivec[16], ecount[16];
    unsigned int num;

    /* 1) set AES key schedule */
    if (AES_set_encrypt_key(key_bytes, 128, &aes_key) < 0) {
        fprintf(stderr, "AES_set_encrypt_key failed\n");
        return 1;
    }

    /* ------------------------------------------------------------ */
    /* A) Test CRYPTO_ctr128_encrypt (uses aes_block)               */
    /* ------------------------------------------------------------ */
    memcpy(ivec, iv_bytes, 16);
    memset(ecount, 0, 16);
    num = 0;

    // CRYPTO_ctr128_encrypt(pt, ct1, sizeof(pt),
    //                       &aes_key, ivec, ecount, &num,
    //                       aes_block);

    // if (memcmp(ct1, ct_expected, sizeof(pt)) != 0) {
    //     fprintf(stderr, "CTR128_encrypt: ciphertext mismatch\n");
    //     return 1;
    // }

    // /* round-trip (CTR is its own inverse) */
    // memcpy(ivec, iv_bytes, 16);
    // memset(ecount, 0, 16);
    // num = 0;
    // CRYPTO_ctr128_encrypt(ct1, ct3, sizeof(pt),
    //                       &aes_key, ivec, ecount, &num,
    //                       aes_block);

    // if (memcmp(ct3, pt, sizeof(pt)) != 0) {
    //     fprintf(stderr, "CTR128_encrypt roundtrip failed\n");
    //     return 1;
    // }

    // /* ------------------------------------------------------------ */
    // /* B) Test CRYPTO_ctr128_encrypt_ctr32 (uses aes_ctr32)         */
    // /* ------------------------------------------------------------ */
    // memcpy(ivec, iv_bytes, 16);
    // memset(ecount, 0, 16);
    // num = 0;

    // CRYPTO_ctr128_encrypt_ctr32(pt, ct2, sizeof(pt),
    //                             &aes_key, ivec, ecount, &num,
    //                             aes_ctr32);

    // /* it should match exactly the same output as (A) */
    // if (memcmp(ct2, ct1, sizeof(pt)) != 0) {
    //     fprintf(stderr, "CTR32_encrypt: ciphertext mismatch\n");
    //     return 1;
    // }

    // /* round-trip via ctr32 */
    // memcpy(ivec, iv_bytes, 16);
    // memset(ecount, 0, 16);
    // num = 0;
    // CRYPTO_ctr128_encrypt_ctr32(ct2, ct4, sizeof(pt),
    //                             &aes_key, ivec, ecount, &num,
    //                             aes_ctr32);

    // if (memcmp(ct4, pt, sizeof(pt)) != 0) {
    //     fprintf(stderr, "CTR32_encrypt roundtrip failed\n");
    //     return 1;
    // }

    // puts("Both CTR128 and CTR32 tests PASS");
    return 0;
}

// int main(void) {
//     // struct {
//     //     const char *hexKey, *hexIV, *hexTag;
//     // } tests[] = {
//     //     { "11754cd72aec309bf52f7687212e8957",
//     //       "3c819d9a9bed087615030b65",
//     //       "250327c674aaf477aef2675748cf6971" },
//     //     { "ca47248ac0b6f8372a97ac43508308ed",
//     //       "ffd2b598feabc9019262d2be",
//     //       "60d20404af527d248d893ae495707d1a" },
//     //     { "db1ad0bd1cf6db0b5d86efdd8914b218",
//     //       "36fad6acb3c98e0138aeb9b1",
//     //       "5ee2ba737d3f2a944b335a81f6653cce" },
//     //     { "1c7135af627c04c32957f33f9ac08590",
//     //       "355c094fa09c8e9281178d34",
//     //       "b6ab2c7d906c9d9ec4c1498d2cbb5029" },
//     //     { "6ca2c11205a6e55ab504dbf3491f8bdc",
//     //       "b1008b650a2fee642175c60d",
//     //       "7a9a225d5f9a0ebfe0e69f371871a672" },
//     //     { "69f2ca78bb5690acc6587302628828d5",
//     //       "701da282cb6b6018dabd00d3",
//     //       "ab1d40dda1798d56687892e2159decfd" },
//     //     { "dcf4e339c487b6797aaca931725f7bbd",
//     //       "2c1d955e35366760ead8817c",
//     //       "32b542c5f344cceceb460a02938d6b0c" },
//     //     { "7658cdbb81572a23a78ee4596f844ee9",
//     //       "1c3baae9b9065961842cbe52",
//     //       "70c7123fc819aa060ed2d3c159b6ea41" },
//     //     { "281a570b1e8f265ee09303ecae0cc46d",
//     //       "8c2941f73cf8713ad5bc13df",
//     //       "a42e5e5f6fb00a9f1206b302edbfd87c" }
//     // };

//     // const size_t TAGLEN = 16, IVLEN = 12, KEYLEN = 16;
//     // unsigned char key[KEYLEN], iv[IVLEN], tag[TAGLEN];
//     // int i, ret;

//     // for (i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
//     //     GCM128_CONTEXT *ctx;
//     //     AES_KEY aes_key;

//     //     /* hex → binary */
//     //     if (hex2bin(tests[i].hexKey, key, KEYLEN) ||
//     //         hex2bin(tests[i].hexIV,  iv,  IVLEN)  ||
//     //         hex2bin(tests[i].hexTag, tag, TAGLEN)) {
//     //         fprintf(stderr, "Bad hex in test %d\n", i);
//     //         continue;
//     //     }

//     //     /* prepare AES key schedule */
//     //     if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
//     //         fprintf(stderr, "AES_set_encrypt_key failed\n");
//     //         return 1;
//     //     }

//     //     /* 1) alloc + init */
//     //     ctx = CRYPTO_gcm128_new(&aes_key, aes_block);
//     //     if (!ctx) {
//     //         fprintf(stderr, "GCM new failed\n");
//     //         return 1;
//     //     }
//     //     CRYPTO_gcm128_init(ctx,       &aes_key, aes_block);

//     //     /* 2) set IV */
//     //     CRYPTO_gcm128_setiv(ctx, iv, IVLEN);

//     //     /* 3) no AAD, so skip CRYPTO_gcm128_aad */

//     //     /* 4) no plaintext: still call encrypt with len=0 */
//     //     ret = CRYPTO_gcm128_encrypt(ctx, NULL, NULL, 0);
//     //     if (ret != 0) {
//     //         fprintf(stderr, "encrypt() error in test %d\n", i);
//     //     }

//     //     /* 5) verify tag: returns 0 on match */
//     //     ret = CRYPTO_gcm128_finish(ctx, tag, TAGLEN);
//     //     printf("Test %d: %s\n", i,
//     //            ret == 0 ? "PASS" : "FAIL");

//     //     /* 6) clean up */
//     //     CRYPTO_gcm128_release(ctx);
//     // }

//         /* your eight “Count=0…7” test vectors */
//     struct {
//         const char *hexKey, *hexIV, *hexPT, *hexAAD, *hexCT, *hexTag;
//     } tests[] = {
//       {
//         "2633d1781ce54f74ac609a5b5209a01f",
//         "7d0e90b7e9f36f760d2dcbd66f352df45f3917afdbe1d0a89cc44be0bd85cf8bf75edbdd33f1d16dad02824d81389210b0f146f3df63f9232d7035eb9e8297a09474985b3e038a5fa6840155d8848fc7c53061ba0f442b84408660a997176ca5bf3473103fd3c9a1de2580b9e539af872259ecae925a8ef50f5a176a069b1fb8",
//         "ae695828625b264e0b13d3c9a539f2cf306a7501cdd35b817b699b2d7c25cf20d2dceec3fa883019db807272fddfdca8e7f672",
//         "584c3cad3035d1427d6f5f1b261e97a5ea7d97c0b88cedf3b1aa5e21e5916805a63964eab4449d8806e7af60618465cf39f82769b7528bba9bb9c04992cd7b9e26efe9be38e1bfeeb41678c52d5ba3508fd7a2b1e8478505bfde",
//         "fbc32a56885100a36c276ff368db9236906021a8cc7500f2b3e78a6ca01546827073ff1103145f139f4d116eb47b84e33c7160",
//         "49589b3a"
//       },
//       /* … Counts 1…7 go here in the same format … */
//     };

//     const int NTESTS = sizeof(tests)/sizeof(tests[0]);
//     const size_t KEYLEN = 16,
//                  IVLEN  = 128,
//                  PTLEN  = 51,
//                  AADLEN = 90,
//                  CTLEN  = PTLEN,
//                  TAGLEN = 4;

//     unsigned char key[KEYLEN],
//                   iv[IVLEN],
//                   pt[PTLEN],
//                   aad[AADLEN],
//                   ct[CTLEN],
//                   tag[TAGLEN],
//                   pt2[PTLEN],
//                   ct2[CTLEN],
//                   tag2[TAGLEN];

//     for (int i = 0; i < NTESTS; i++) {
//         AES_KEY aes_key;
//         GCM128_CONTEXT *ctx;
//         int pass_encrypt = 1, pass_decrypt = 1;

//         /* hex → bin all inputs & expected outputs */
//         if (hex2bin(tests[i].hexKey, key, KEYLEN)        ||
//             hex2bin(tests[i].hexIV,  iv,  IVLEN)         ||
//             hex2bin(tests[i].hexPT,  pt,  PTLEN)         ||
//             hex2bin(tests[i].hexAAD, aad, AADLEN)       ||
//             hex2bin(tests[i].hexCT,  ct,  CTLEN)        ||
//             hex2bin(tests[i].hexTag, tag, TAGLEN))
//         {
//             fprintf(stderr, "Bad hex in test %d\n", i);
//             continue;
//         }

//         /* AES key schedule */
//         if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
//             fprintf(stderr, "AES_set_encrypt_key failed\n");
//             return 1;
//         }

//         /****************************************************************
//          * 1) “Plain” GCM encrypt → CT + tag
//          ****************************************************************/
//         ctx = CRYPTO_gcm128_new(&aes_key, aes_block);
//         CRYPTO_gcm128_init(ctx,        &aes_key, aes_block);
//         CRYPTO_gcm128_setiv(ctx,       iv,  IVLEN);
//         CRYPTO_gcm128_aad(ctx,         aad, AADLEN);
//         if (CRYPTO_gcm128_encrypt(ctx, pt, ct2, PTLEN) != PTLEN)
//             pass_encrypt = 0;
//         CRYPTO_gcm128_tag(ctx, tag2,   TAGLEN);

//         if (memcmp(ct2, ct, CTLEN)!=0 || memcmp(tag2, tag, TAGLEN)!=0)
//             pass_encrypt = 0;

//         CRYPTO_gcm128_release(ctx);

//         /****************************************************************
//          * 2) “Plain” GCM decrypt → verify tag + PT round-trip
//          ****************************************************************/
//         ctx = CRYPTO_gcm128_new(&aes_key, aes_block);
//         CRYPTO_gcm128_init(ctx,        &aes_key, aes_block);
//         CRYPTO_gcm128_setiv(ctx,       iv,  IVLEN);
//         CRYPTO_gcm128_aad(ctx,         aad, AADLEN);
//         if (CRYPTO_gcm128_decrypt(ctx, ct, pt2, PTLEN) != PTLEN)
//             pass_decrypt = 0;
//         if (CRYPTO_gcm128_finish(ctx, tag, TAGLEN) != 0)
//             pass_decrypt = 0;
//         CRYPTO_gcm128_release(ctx);

//         /****************************************************************
//          * 3) “CTR32” GCM encrypt → CT + tag
//          ****************************************************************/
//         ctx = CRYPTO_gcm128_new(&aes_key, aes_block);
//         CRYPTO_gcm128_init(ctx,        &aes_key, aes_block);
//         CRYPTO_gcm128_setiv(ctx,       iv,  IVLEN);
//         CRYPTO_gcm128_aad(ctx,         aad, AADLEN);
//         if (CRYPTO_gcm128_encrypt_ctr32(ctx, pt, ct2, PTLEN, aes_ctr) != PTLEN)
//             pass_encrypt = 0;
//         CRYPTO_gcm128_tag(ctx, tag2,   TAGLEN);
//         if (memcmp(ct2, ct, CTLEN)!=0 || memcmp(tag2, tag, TAGLEN)!=0)
//             pass_encrypt = 0;
//         CRYPTO_gcm128_release(ctx);

//         /****************************************************************
//          * 4) “CTR32” GCM decrypt → verify tag + PT round-trip
//          ****************************************************************/
//         ctx = CRYPTO_gcm128_new(&aes_key, aes_block);
//         CRYPTO_gcm128_init(ctx,        &aes_key, aes_block);
//         CRYPTO_gcm128_setiv(ctx,       iv,  IVLEN);
//         CRYPTO_gcm128_aad(ctx,         aad, AADLEN);
//         if (CRYPTO_gcm128_decrypt_ctr32(ctx, ct, pt2, PTLEN, aes_ctr) != PTLEN)
//             pass_decrypt = 0;
//         if (CRYPTO_gcm128_finish(ctx, tag, TAGLEN) != 0)
//             pass_decrypt = 0;
//         CRYPTO_gcm128_release(ctx);

//         printf("Test %d: encrypt %s, decrypt %s\n",
//                i,
//                pass_encrypt ? "PASS" : "FAIL",
//                pass_decrypt ? "PASS" : "FAIL");
//     }

//     return 0;
// }