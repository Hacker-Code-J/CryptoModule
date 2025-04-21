/* File: include/api.h */

#ifndef CRYPTOMODULE_API_H
#define CRYPTOMODULE_API_H

/* -----------------------------------------------------------------------------
 * Master API header for CryptoModule.
 * This file aggregates all relevant algorithm headers into a single include.
 * ---------------------------------------------------------------------------*/

#include <stdio.h>      // For FILE
#include <stdlib.h>     // For malloc, free
#include <stdbool.h>    // For bool
#include <assert.h>     // For assert
#include <string.h>     // For memcpy, memset
#include <stdint.h>     // For uint8_t, uint32_t, etc.
#include <stddef.h>     // For size_t

typedef int8_t     i8;
typedef int32_t    i32;
typedef int64_t    i64;

typedef uint8_t    u8;
typedef uint32_t   u32;
typedef uint64_t   u64;

/* Optionally define convenience ��enums��, ��error codes��, or ��global�� functions*/
typedef enum {
    CRYPTOMODULE_OK = 0,
    CRYPTOMODULE_ERR_INVALID_INPUT,
    CRYPTOMODULE_ERR_CRYPTO_FAILURE,
    /* ... */
} cryptomodule_status_t;

/* Example of a top-level initialization function. */
#ifdef __cplusplus
extern "C" {
#endif

cryptomodule_status_t cryptomodule_init(void);
cryptomodule_status_t cryptomodule_cleanup(void);

/* Crypto Module */
typedef struct {
    const char *name;
    cryptomodule_status_t (*init)(void);
    cryptomodule_status_t (*cleanup)(void);
} CryptoModuleApi;
typedef struct {
    const CryptoModuleApi *api;
} CryptoModuleContext;
typedef struct {
    const CryptoModuleApi *api;
    CryptoModuleContext *ctx;
} CryptoModuleInternal;

/* Core Header */
#include "cryptomodule_utils.h"
#include "cryptomodule_test.h"

/* Block ciphers */
#include "block_cipher/block_cipher_api.h"
// #include "block_cipher/block_cipher_aes.h"
// #include "block_cipher/block_cipher_aria.h"
// #include "block_cipher/block_cipher_lea.h"

/* Modes of operation */
#include "mode/mode_api.h"
// #include "mode/mode_ecb.h"
// #include "mode/mode_cbc.h"
// #include "mode/mode_ctr.h"
// #include "mode/mode_gcm.h"

/* RNG */
// #include "ctr_drbg.h"

/* Hash functions */
// #include "sha2.h"
// #include "sha3.h"
// #include "lsh.h"

/* MAC */
// #include "hmac.h"

/* KDF */
// #include "pbkdf.h"

/* Key Setup */
// #include "ecdh.h"

/* Signature */
// #include "rsapss.h"
// #include "ecdsa.h"
// #include "eckcdsa.h"


#ifdef __cplusplus
}
#endif

#endif /* CRYPTOMODULE_API_H */
