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
#include <crypto/hash/hash_algs.h>

/*
 * Return the hash mapping entry 'hm' associated with given hash name
 * 'hash_name'. The function returns 0 on success, -1 on error. 'hm'
 * is only meaningful on success.
 */
int get_hash_by_name(const char *hash_name, const hash_mapping **hm)
{
	const hash_mapping *_hm = NULL;
	int ret, check;
	u8 i;

	MUST_HAVE(((hash_name != NULL) && (hm != NULL)), ret, err);

	ret = -1;
	for (i = 0, _hm = &hash_maps[i]; _hm->type != UNKNOWN_HASH_ALG;
	     _hm = &hash_maps[++i]) {
		const char *exp_name = (const char *)_hm->name;

		if ((!are_str_equal(hash_name, exp_name, &check)) && check) {
			(*hm) = _hm;
			ret = 0;
			break;
		}
	}

err:
	return ret;
}

/*
 * Return the hash mapping entry 'hm' associated with given hash type value.
 * The function returns 0 on success, -1 on error. 'hm' is not meaningfull
 * on error.
 */
int get_hash_by_type(hash_alg_type hash_type, const hash_mapping **hm)
{
	const hash_mapping *_hm = NULL;
	int ret;
	u8 i;

	MUST_HAVE((hm != NULL), ret, err);

	ret = -1;
	for (i = 0, _hm = &hash_maps[i]; _hm->type != UNKNOWN_HASH_ALG;
	     _hm = &hash_maps[++i]) {
		if (_hm->type == hash_type) {
			(*hm) = _hm;
			ret = 0;
			break;
		}
	}

err:
	return ret;
}

/*
 * Returns respectively in digest_size and block_size param the digest size
 * and block size for given hash function, if return value of the function is 0.
 * If return value is -1, then the hash algorithm is not known and output
 * parameters are not modified.
 */
int get_hash_sizes(hash_alg_type hash_type, u8 *digest_size, u8 *block_size)
{
	const hash_mapping *m;
	int ret;
	u8 i;

	ret = -1;
	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
		if (m->type == hash_type) {
			if (digest_size != NULL) {
				(*digest_size) = m->digest_size;
			}
			if (block_size != NULL) {
				(*block_size) = m->block_size;
			}
			ret = 0;
			break;
		}
	}

	return ret;
}

/*
 * Helper that sanity checks the provided hash mapping against our
 * constant ones. Returns 0 on success, -1 on error.
 */
int hash_mapping_callbacks_sanity_check(const hash_mapping *h)
{
	const hash_mapping *m;
	int ret = -1, check;
	u8 i;

	MUST_HAVE((h != NULL), ret, err);

	/* We just check is our mapping is indeed
	 * one of the registered mappings.
	 */
	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
		if (m->type == h->type) {
			if ((!are_str_equal_nlen(m->name, h->name, MAX_HASH_ALG_NAME_LEN, &check)) && (!check)){
				goto err;
			} else if (m->digest_size != h->digest_size) {
				goto err;
			} else if(m->block_size != h->block_size) {
				goto err;
			} else if(m->hfunc_init != h->hfunc_init) {
				goto err;
			} else if(m->hfunc_update != h->hfunc_update) {
				goto err;
			} else if(m->hfunc_finalize != h->hfunc_finalize) {
				goto err;
			} else if(m->hfunc_scattered != h->hfunc_scattered) {
				goto err;
			} else{
				ret = 0;
			}
		}
	}

err:
	return ret;
}

/*****************************************/
/* Trampolines to each specific function to
 * handle typing of our generic union structure.
 */
#ifdef HASH_SHA256
int _sha256_init(hash_context * hctx)
{
	return sha256_init((sha256_context*)hctx);
}
int _sha256_update(hash_context * hctx, const unsigned char *chunk, u32 chunklen)
{
	return sha256_update((sha256_context*)hctx, chunk, chunklen);
}
int _sha256_final(hash_context * hctx, unsigned char *output)
{
	return sha256_final((sha256_context*)hctx, output);
}
#endif
#ifdef HASH_SHA3_256
int _sha3_256_init(hash_context * hctx)
{
	return sha3_256_init((sha3_256_context*)hctx);
}
int _sha3_256_update(hash_context * hctx, const unsigned char *chunk, u32 chunklen)
{
	return sha3_256_update((sha3_256_context*)hctx, chunk, chunklen);
}
int _sha3_256_final(hash_context * hctx, unsigned char *output)
{
	return sha3_256_final((sha3_256_context*)hctx, output);
}
#endif
#ifdef HASH_SHAKE256
int _shake256_init(hash_context * hctx)
{
	return shake256_init((shake256_context*)hctx);
}
int _shake256_update(hash_context * hctx, const unsigned char *chunk, u32 chunklen)
{
	return shake256_update((shake256_context*)hctx, chunk, chunklen);
}
int _shake256_final(hash_context * hctx, unsigned char *output)
{
	return shake256_final((shake256_context*)hctx, output);
}
#endif
