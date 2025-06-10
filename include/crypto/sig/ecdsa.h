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
#include <crypto/crypto_ecc_config.h>
#include <crypto/crypto_ecc_types.h>
#ifdef SIG_ECDSA

#ifndef __ECDSA_H__
#define __ECDSA_H__

#include <crypto/sig/ecdsa_common.h>

int ecdsa_init_pub_key(ec_pub_key *out_pub, const ec_priv_key *in_priv);

int ecdsa_siglen(u16 p_bit_len, u16 q_bit_len, u8 hsize, u8 blocksize, u8 *siglen);

int _ecdsa_sign_init(struct ec_sign_context *ctx);

int _ecdsa_sign_update(struct ec_sign_context *ctx,
		       const u8 *chunk, u32 chunklen);

int _ecdsa_sign_finalize(struct ec_sign_context *ctx, u8 *sig, u8 siglen);

int _ecdsa_verify_init(struct ec_verify_context *ctx,
		       const u8 *sig, u8 siglen);

int _ecdsa_verify_update(struct ec_verify_context *ctx,
			 const u8 *chunk, u32 chunklen);

int _ecdsa_verify_finalize(struct ec_verify_context *ctx);

int ecdsa_public_key_from_sig(ec_pub_key *out_pub1, ec_pub_key *out_pub2, const ec_params *params,
                                const u8 *sig, u8 siglen, const u8 *hash, u8 hsize);

#endif /* __ECDSA_H__ */
#endif /* SIG_ECDSA */
