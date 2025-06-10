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
#ifndef __SIG_ALGS_INTERNAL_H__
#define __SIG_ALGS_INTERNAL_H__

#include <crypto/hash/hash_algs.h>
#include <crypto/curves/curves.h>
#include <crypto/sig/ec_key.h>
#include <crypto/sig/ecdsa.h>

#if (EC_MAX_SIGLEN == 0)
#error "It seems you disabled all signature schemes in lib_ecc_config.h"
#endif

/*
 * All the signature algorithms we support are abstracted using the following
 * structure (and following map) which provides for each hash alg its
 * digest size, its block size and the associated scattered function.
 */
typedef struct {
	ec_alg_type type;
	const char *name;

	int (*siglen) (u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize, u8 *siglen);

	int (*gen_priv_key) (ec_priv_key *priv_key);
	int (*init_pub_key) (ec_pub_key *pub_key, const ec_priv_key *priv_key);

	int (*sign_init) (struct ec_sign_context * ctx);
	int (*sign_update) (struct ec_sign_context * ctx,
			    const u8 *chunk, u32 chunklen);
	int (*sign_finalize) (struct ec_sign_context * ctx,
			      u8 *sig, u8 siglen);
	int (*sign) (u8 *sig, u8 siglen, const ec_key_pair *key_pair,
		     const u8 *m, u32 mlen, int (*rand) (nn_t out, nn_src_t q),
		     ec_alg_type sig_type, hash_alg_type hash_type,
		     const u8 *adata, u16 adata_len);

	int (*verify_init) (struct ec_verify_context * ctx,
			    const u8 *sig, u8 siglen);
	int (*verify_update) (struct ec_verify_context * ctx,
			      const u8 *chunk, u32 chunklen);
	int (*verify_finalize) (struct ec_verify_context * ctx);
	int (*verify) (const u8 *sig, u8 siglen, const ec_pub_key *pub_key,
	      const u8 *m, u32 mlen, ec_alg_type sig_type,
	      hash_alg_type hash_type, const u8 *adata, u16 adata_len);
	int (*verify_batch) (const u8 **s, const u8 *s_len, const ec_pub_key **pub_keys,
              const u8 **m, const u32 *m_len, u32 num, ec_alg_type sig_type,
              hash_alg_type hash_type, const u8 **adata, const u16 *adata_len,
	      verify_batch_scratch_pad *scratch_pad_area, u32 *scratch_pad_area_len);

} ec_sig_mapping;

/* Sanity check to ensure our sig mapping does not contain
 * NULL pointers
 */
static inline int sig_mapping_sanity_check(const ec_sig_mapping *sm)
{
	int ret;

	MUST_HAVE(((sm != NULL) && (sm->name != NULL) && (sm->siglen != NULL) &&
		    (sm->gen_priv_key != NULL) && (sm->init_pub_key != NULL) &&
		    (sm->sign_init != NULL) && (sm->sign_update != NULL) &&
		    (sm->sign_finalize != NULL) && (sm->sign != NULL) &&
		    (sm->verify_init != NULL) && (sm->verify_update != NULL) &&
		    (sm->verify_finalize != NULL) && (sm->verify != NULL) &&
		    (sm->verify_batch != NULL)),
		   ret, err);

	ret = 0;

err:
	return ret;
}

/*
 * Each specific signature scheme need to maintain some specific
 * data between calls to init()/update()/finalize() functions.
 *
 * Each scheme provides a specific structure for that purpose
 * (in its .h file) which we include in the union below. A field
 * of that type (.sign_data) is then included in the generic
 * struct ec_sign_context below.
 *
 * The purpose of that work is to allow static declaration and
 * allocation of common struct ec_sign_context with enough room
 * available for all supported signature types.
 */

typedef union {
#if defined(SIG_ECDSA) || defined(SIG_DECDSA)		/* ECDSA and DECDSA */
	ecdsa_sign_data ecdsa;
#endif
} sig_sign_data;

/*
 * The 'struct ec_sign_context' below provides a persistent state
 * between successive calls to ec_sign_{init,update,finalize}().
 */
struct ec_sign_context {
	word_t ctx_magic;
	const ec_key_pair *key_pair;
	int (*rand) (nn_t out, nn_src_t q);
	const hash_mapping *h;
	const ec_sig_mapping *sig;

	sig_sign_data sign_data;

	/* Optional ancillary data. This data is
	 * optionnally used by the signature algorithm.
	 */
	const u8 *adata;
	u16 adata_len;
};

#define SIG_SIGN_MAGIC ((word_t)(0x4ed73cfe4594dfd3ULL))
static inline int sig_sign_check_initialized(struct ec_sign_context *ctx)
{
	return (((ctx == NULL) || (ctx->ctx_magic != SIG_SIGN_MAGIC)) ? -1 : 0);
}

typedef union {
#if defined(SIG_ECDSA) || defined(SIG_DECDSA)		/* ECDSA and DECDSA */
	ecdsa_verify_data ecdsa;
#endif
} sig_verify_data;

/*
 * The 'struct ec_verify_context' below provides a persistent state
 * between successive calls to ec_verify_{init,update,finalize}().
 */
struct ec_verify_context {
	word_t ctx_magic;
	const ec_pub_key *pub_key;
	const hash_mapping *h;
	const ec_sig_mapping *sig;

	sig_verify_data verify_data;

	/* Optional ancillary data. This data is
	 * optionnally used by the signature algorithm.
	 */
	const u8 *adata;
	u16 adata_len;
};

#define SIG_VERIFY_MAGIC ((word_t)(0x7e0d42d13e3159baULL))
static inline int sig_verify_check_initialized(struct ec_verify_context *ctx)
{
	return (((ctx == NULL) || (ctx->ctx_magic != SIG_VERIFY_MAGIC)) ? -1 : 0);
}

/* Generic signature and verification APIs that will in fact call init / update / finalize in
 * backend. Used for signature and verification functions that support these streaming APIs.
 *
 */
int generic_ec_sign(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
	     const u8 *m, u32 mlen, int (*rand) (nn_t out, nn_src_t q),
	     ec_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len);
int generic_ec_verify(const u8 *sig, u8 siglen, const ec_pub_key *pub_key,
	      const u8 *m, u32 mlen, ec_alg_type sig_type,
	      hash_alg_type hash_type, const u8 *adata, u16 adata_len);

/* Generic init / update / finalize functions returning an error and telling that they are
 * unsupported.
 */
int unsupported_sign_init(struct ec_sign_context * ctx);
int unsupported_sign_update(struct ec_sign_context * ctx,
		    const u8 *chunk, u32 chunklen);
int unsupported_sign_finalize(struct ec_sign_context * ctx,
		      u8 *sig, u8 siglen);

int is_sign_streaming_mode_supported(ec_alg_type sig_type, int *check);

int unsupported_verify_init(struct ec_verify_context * ctx,
		    const u8 *sig, u8 siglen);
int unsupported_verify_update(struct ec_verify_context * ctx,
		      const u8 *chunk, u32 chunklen);
int unsupported_verify_finalize(struct ec_verify_context * ctx);

int is_verify_streaming_mode_supported(ec_alg_type sig_type, int *check);

int is_sign_deterministic(ec_alg_type sig_type, int *check);

int is_verify_batch_mode_supported(ec_alg_type sig_type, int *check);

int unsupported_verify_batch(const u8 **s, const u8 *s_len, const ec_pub_key **pub_keys,
              const u8 **m, const u32 *m_len, u32 num, ec_alg_type sig_type,
              hash_alg_type hash_type, const u8 **adata, const u16 *adata_len,
	      verify_batch_scratch_pad *scratch_pad_area, u32 *scratch_pad_area_len);

/*
 * Each signature algorithm supported by the library and implemented
 * in ec{,ck,s,fs,g,r}dsa.{c,h} is referenced below.
 */
#define MAX_SIG_ALG_NAME_LEN	0
static const ec_sig_mapping ec_sig_maps[] = {
#ifdef SIG_ECDSA
	{.type = ECDSA,
	 .name = "ECDSA",
	 .siglen = ecdsa_siglen,
	 .gen_priv_key = generic_gen_priv_key,
	 .init_pub_key = ecdsa_init_pub_key,
	 .sign_init = _ecdsa_sign_init,
	 .sign_update = _ecdsa_sign_update,
	 .sign_finalize = _ecdsa_sign_finalize,
	 .sign = generic_ec_sign,
	 .verify_init = _ecdsa_verify_init,
	 .verify_update = _ecdsa_verify_update,
	 .verify_finalize = _ecdsa_verify_finalize,
	 .verify = generic_ec_verify,
	 .verify_batch = unsupported_verify_batch,
	 },
#if (MAX_SIG_ALG_NAME_LEN < 6)
#undef MAX_SIG_ALG_NAME_LEN
#define MAX_SIG_ALG_NAME_LEN 6
#endif /* MAX_SIG_ALG_NAME_LEN */
#endif /* SIG_ECDSA */
	{.type = UNKNOWN_ALG,	/* Needs to be kept last */
	 .name = "UNKNOWN",
	 .siglen = 0,
	 .gen_priv_key = NULL,
	 .init_pub_key = NULL,
	 .sign_init = NULL,
	 .sign_update = NULL,
	 .sign_finalize = NULL,
	 .sign = NULL,
	 .verify_init = NULL,
	 .verify_update = NULL,
	 .verify_finalize = NULL,
	 .verify = NULL,
	 .verify_batch = NULL,
	 },
};

/*
 * For a given raw signature, the structured version is produced by prepending
 * three bytes providing specific sig alg, hash alg and curve.
 */
#define EC_STRUCTURED_SIG_EXPORT_SIZE(siglen)  (u8)((siglen) + (u8)(3 * sizeof(u8)))
#define EC_STRUCTURED_SIG_MAX_EXPORT_SIZE (EC_MAX_SIGLEN + 3)

/* Sanity check */
#if EC_STRUCTURED_SIG_MAX_EXPORT_SIZE > 255
#error "All structured signatures sizes are expected to fit on an u8."
#endif
#endif /* __SIG_ALGS_INTERNAL_H__ */
