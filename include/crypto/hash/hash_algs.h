/*
 *  Copyright (C) 2017 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
 *
 *  Contributors:
 *      Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
 *      Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#ifndef __HASH_ALGS_H__
#define __HASH_ALGS_H__

#include <crypto/crypto_ecc_config.h>
#include <crypto/crypto_ecc_types.h>
#include <crypto/words/words.h>
#include <crypto/hash/sha256.h>
#include <crypto/hash/sha3-256.h>
#include <crypto/hash/shake256.h>
#include <crypto/utils/utils.h>

#if (MAX_DIGEST_SIZE == 0)
#error "It seems you disabled all hash algorithms in lib_ecc_config.h"
#endif

#if (MAX_BLOCK_SIZE == 0)
#error "It seems you disabled all hash algorithms in lib_ecc_config.h"
#endif

typedef union {
#ifdef SHA256_BLOCK_SIZE
	sha256_context sha256;
#endif
#ifdef SHA3_256_BLOCK_SIZE
	sha3_256_context sha3_256;
#endif
#ifdef SHAKE256_BLOCK_SIZE
	shake256_context shake256;
#endif
} hash_context;

typedef int (*_hfunc_init) (hash_context * hctx);
typedef int (*_hfunc_update) (hash_context * hctx,
			      const unsigned char *chunk, u32 chunklen);
typedef int (*_hfunc_finalize) (hash_context * hctx, unsigned char *output);
typedef int (*_hfunc_scattered) (const unsigned char **inputs,
				 const u32 *ilens, unsigned char *output);

/*****************************************/
/* Trampolines to each specific function to
 * handle typing of our generic union structure.
 */
#ifdef HASH_SHA256
int _sha256_init(hash_context * hctx);
int _sha256_update(hash_context * hctx, const unsigned char *chunk, u32 chunklen);
int _sha256_final(hash_context * hctx, unsigned char *output);
#endif
#ifdef HASH_SHA3_256
int _sha3_256_init(hash_context * hctx);
int _sha3_256_update(hash_context * hctx, const unsigned char *chunk, u32 chunklen);
int _sha3_256_final(hash_context * hctx, unsigned char *output);
#endif
#ifdef HASH_SHAKE256
int _shake256_init(hash_context * hctx);
int _shake256_update(hash_context * hctx, const unsigned char *chunk, u32 chunklen);
int _shake256_final(hash_context * hctx, unsigned char *output);
#endif

/*
 * All the hash algorithms we support are abstracted using the following
 * structure (and following map) which provides for each hash alg its
 * digest size, its block size and the associated scattered function.
 */
typedef struct {
	hash_alg_type type;
	const char *name;
	u8 digest_size;
	u8 block_size;
	_hfunc_init hfunc_init;
	_hfunc_update hfunc_update;
	_hfunc_finalize hfunc_finalize;
	_hfunc_scattered hfunc_scattered;
} hash_mapping;

static inline int hash_mapping_sanity_check(const hash_mapping *hm)
{
	int ret;

	MUST_HAVE(((hm != NULL) && (hm->name != NULL) && (hm->hfunc_init != NULL) &&
		    (hm->hfunc_update != NULL) && (hm->hfunc_finalize != NULL) &&
		    (hm->hfunc_scattered != NULL)), ret, err);

	ret = 0;

err:
	return ret;
}

#define MAX_HASH_ALG_NAME_LEN	0
static const hash_mapping hash_maps[] = {
#ifdef HASH_SHA256
	{.type = SHA256,	/* SHA256 */
	 .name = "SHA256",
	 .digest_size = SHA256_DIGEST_SIZE,
	 .block_size = SHA256_BLOCK_SIZE,
	 .hfunc_init = _sha256_init,
	 .hfunc_update = _sha256_update,
	 .hfunc_finalize = _sha256_final,
	 .hfunc_scattered = sha256_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* HASH_SHA256 */
#ifdef HASH_SHA3_256
	{.type = SHA3_256,	/* SHA3_256 */
	 .name = "SHA3_256",
	 .digest_size = SHA3_256_DIGEST_SIZE,
	 .block_size = SHA3_256_BLOCK_SIZE,
	 .hfunc_init = _sha3_256_init,
	 .hfunc_update = _sha3_256_update,
	 .hfunc_finalize = _sha3_256_final,
	 .hfunc_scattered = sha3_256_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* HASH_SHA3_256 */
#ifdef HASH_SHAKE256
	{.type = SHAKE256,	/* SHAKE256 */
	 .name = "SHAKE256",
	 .digest_size = SHAKE256_DIGEST_SIZE,
	 .block_size = SHAKE256_BLOCK_SIZE,
	 .hfunc_init = _shake256_init,
	 .hfunc_update = _shake256_update,
	 .hfunc_finalize = _shake256_final,
	 .hfunc_scattered = shake256_scattered},
#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* HASH_SHAKE256 */
	{.type = UNKNOWN_HASH_ALG,	/* Needs to be kept last */
	 .name = "UNKNOWN",
	 .digest_size = 0,
	 .block_size = 0,
	 .hfunc_init = NULL,
	 .hfunc_update = NULL,
	 .hfunc_finalize = NULL,
	 .hfunc_scattered = NULL},
};

int get_hash_by_name(const char *hash_name, const hash_mapping **hm);
int get_hash_by_type(hash_alg_type hash_type, const hash_mapping **hm);
int get_hash_sizes(hash_alg_type hash_type, u8 *digest_size, u8 *block_size);
int hash_mapping_callbacks_sanity_check(const hash_mapping *h);

#endif /* __HASH_ALGS_H__ */
