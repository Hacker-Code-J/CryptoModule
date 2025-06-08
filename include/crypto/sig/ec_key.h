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

#endif /* __EC_KEY_H__ */