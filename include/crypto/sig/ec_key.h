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
#ifndef __EC_KEY_H__
#define __EC_KEY_H__

#include <crypto/crypto_ecc_config.h>
#include <crypto/crypto_ecc_types.h>
#include <crypto/fp/fp.h>
#include <crypto/curves/ec_params.h>
#include <crypto/nn/nn_rand.h>
#include <crypto/nn/nn_add.h>
#include <crypto/nn/nn_logical.h>
#include <crypto/curves/prj_pt.h>
#include <crypto/hash/hash_algs.h>

/* Enum for exported keys */
typedef enum {
	EC_PUBKEY = 0,
	EC_PRIVKEY = 1,
} ec_key_type;

/*
 * Declarations for EC private keys
 */
#define PRIV_KEY_MAGIC ((word_t)(0x2feb91e938a4855dULL)) /* Magic value to check if a private key is initialized */
typedef struct {
	/* A key type can only be used for a given sig alg */
	ec_alg_type key_type;

	/* Elliptic curve parameters */
	const ec_params *params;

	/*
	 * Private key (usually an integer in ]0,q[, where q is
	 * the order of G, the generator of the group
	 * on the curve, or a derivative of this).
	 *
	 * For the specific case of EdDSA, this value will instead hold the
	 * digest derivation of the secret value sk that is twice the size of
	 * the digest size.
	 */
	nn x;

	word_t magic;
} ec_priv_key;

/* NOTE1: in the specific case of EdDSA, the hash size dictates the size of the
 * private keys. Although EdDSA only uses specific hash algorithms, we are being
 * conservative here by taking the maximum digest size (hence accepting losing some space
 * wen storing the private key for more simplicity).
 *
 * NOTE2: we use MAX_DIGEST_SIZE as the basis for EdDSA private key size instead of
 * (MAX_DIGEST_SIZE / 2) because we store the EdDSA private key in its *derived* formed,
 * meaning that it is twice the size of a regular standardized private key.
 *
 */
#define EC_PRIV_KEY_MAX_SIZE	(LOCAL_MAX(BYTECEIL(CURVES_MAX_Q_BIT_LEN), BYTECEIL(CURVES_MAX_P_BIT_LEN)))

#define EC_PRIV_KEY_EXPORT_SIZE(priv_key)			\
	((u8)(LOCAL_MAX(BYTECEIL((priv_key)->params->ec_gen_order_bitlen), BYTECEIL((priv_key)->params->ec_fp.p_bitlen))))


#define EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE	(EC_PRIV_KEY_MAX_SIZE + 3)
#if (EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE > 255)
#error "All structured priv keys size are expected to fit on an u8."
#endif

#define EC_STRUCTURED_PRIV_KEY_EXPORT_SIZE(priv_key)			\
	((u8)(EC_PRIV_KEY_EXPORT_SIZE(priv_key) + (3 * sizeof(u8))))

int priv_key_check_initialized(const ec_priv_key *A);
int priv_key_check_initialized_and_type(const ec_priv_key *A,
					ec_alg_type sig_type);

int ec_priv_key_import_from_buf(ec_priv_key *priv_key,
				const ec_params *params,
				const u8 *priv_key_buf, u8 priv_key_buf_len,
				ec_alg_type ec_key_alg);
int ec_priv_key_export_to_buf(const ec_priv_key *priv_key, u8 *priv_key_buf,
			      u8 priv_key_buf_len);

int ec_structured_priv_key_import_from_buf(ec_priv_key *priv_key,
					   const ec_params *params,
					   const u8 *priv_key_buf,
					   u8 priv_key_buf_len,
					   ec_alg_type ec_key_alg);
int ec_structured_priv_key_export_to_buf(const ec_priv_key *priv_key,
					 u8 *priv_key_buf,
					 u8 priv_key_buf_len);

/*
 * Declarations for EC public keys
 */

#define PUB_KEY_MAGIC ((word_t)(0x31327f37741ffb76ULL))
typedef struct {
	/* A key type can only be used for a given sig alg */
	ec_alg_type key_type;

	/* Elliptic curve parameters */
	const ec_params *params;

	/* Public key, i.e. y = xG mod p */
	prj_pt y;

	word_t magic;
} ec_pub_key;

#define EC_PUB_KEY_MAX_SIZE (3 * BYTECEIL(CURVES_MAX_P_BIT_LEN))

#define EC_PUB_KEY_EXPORT_SIZE(pub_key)                                 \
	(3 * BYTECEIL((pub_key)->params->ec_curve.a.ctx->p_bitlen))

#define EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE	(EC_PUB_KEY_MAX_SIZE + 3)
#if (EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE > 255)
#error "All structured pub keys size are expected to fit on an u8."
#endif
#define EC_STRUCTURED_PUB_KEY_EXPORT_SIZE(pub_key)			\
	((u8)(EC_PUB_KEY_EXPORT_SIZE(pub_key) + (u8)(3 * sizeof(u8))))

int pub_key_check_initialized(const ec_pub_key *A);
int pub_key_check_initialized_and_type(const ec_pub_key *A,
				       ec_alg_type sig_type);

int ec_pub_key_import_from_buf(ec_pub_key *pub_key, const ec_params *params,
			       const u8 *pub_key_buf, u8 pub_key_buf_len,
			       ec_alg_type ec_key_alg);
int ec_pub_key_export_to_buf(const ec_pub_key *pub_key, u8 *pub_key_buf,
			     u8 pub_key_buf_len);

int ec_pub_key_import_from_aff_buf(ec_pub_key *pub_key, const ec_params *params,
			       const u8 *pub_key_buf, u8 pub_key_buf_len,
			       ec_alg_type ec_key_alg);

int ec_pub_key_export_to_aff_buf(const ec_pub_key *pub_key, u8 *pub_key_buf,
			     u8 pub_key_buf_len);

int ec_structured_pub_key_import_from_buf(ec_pub_key *pub_key,
					  const ec_params *params,
					  const u8 *pub_key_buf,
					  u8 pub_key_buf_len,
					  ec_alg_type ec_key_alg);
int ec_structured_pub_key_export_to_buf(const ec_pub_key *pub_key,
					u8 *pub_key_buf, u8 pub_key_buf_len);

/*
 * Declarations for EC key pairs
 */

typedef struct {
	ec_priv_key priv_key;
	ec_pub_key pub_key;
} ec_key_pair;

int key_pair_check_initialized(const ec_key_pair *A);

int key_pair_check_initialized_and_type(const ec_key_pair *A,
					 ec_alg_type sig_type);

int ec_key_pair_import_from_priv_key_buf(ec_key_pair *kp,
					 const ec_params *params,
					 const u8 *priv_key, u8 priv_key_len,
					 ec_alg_type ec_key_alg);
int ec_key_pair_gen(ec_key_pair *kp, const ec_params *params, ec_alg_type ec_key_alg);

int ec_structured_key_pair_import_from_priv_key_buf(ec_key_pair *kp,
						    const ec_params *params,
						    const u8 *priv_key_buf,
						    u8 priv_key_buf_len,
						    ec_alg_type ec_key_alg);
/*
 * NOTE: please use the following API with care as it does not check the consistency
 * between the private and public keys! On one side, this "saves" a costly
 * scalar multiplication when there is confidence in the source of the buffers,
 * but on the other side the user of the API MUST check the source (integrity)
 * of the private/public key pair. If unsure, it is advised to use the
 * ec_structured_key_pair_import_from_priv_key_buf API that safely derives the
 * public key from the private key.
 *
 */
int ec_structured_key_pair_import_from_buf(ec_key_pair *kp,
					   const ec_params *params,
					   const u8 *priv_key_buf,
					   u8 priv_key_buf_len,
					   const u8 *pub_key_buf,
					   u8 pub_key_buf_len,
					   ec_alg_type ec_key_alg);

int generic_gen_priv_key(ec_priv_key *priv_key);

/* Type used for batch verification */
typedef struct {
        nn number;
        prj_pt point;
	u32 index;
} verify_batch_scratch_pad;


#endif /* __EC_KEY_H__ */