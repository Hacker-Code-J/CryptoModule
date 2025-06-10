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
#ifndef __LIB_ECC_TYPES_H__
#define __LIB_ECC_TYPES_H__

#include <crypto/crypto_ecc_config.h>

/* Signature algorithm types */
typedef enum {
	UNKNOWN_ALG = 0,
#ifdef SIG_ECDSA
	ECDSA = 1,
#endif
#ifdef SIG_ECKCDSA
	ECKCDSA = 2,
#endif
} ec_alg_type;

/* Hash algorithm types */
typedef enum {
	UNKNOWN_HASH_ALG = 0,
#ifdef HASH_SHA256
	SHA256 = 2,
#endif
#ifdef HASH_SHA3_256
	SHA3_256 = 6,
#endif
#ifdef HASH_SHAKE256
	SHAKE256 = 12,
#endif
} hash_alg_type;

/* All curves we support */
typedef enum {
	UNKNOWN_CURVE = 0,
#ifdef CURVE_FRP256V1
	FRP256V1 = 1,
#endif
#ifdef CURVE_SECP192R1
	SECP192R1 = 2,
#endif
#ifdef CURVE_SECP224R1
	SECP224R1 = 3,
#endif
#ifdef CURVE_SECP256R1
	SECP256R1 = 4,
#endif
/* ADD curves type here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */
} ec_curve_type;

#endif /* __LIB_ECC_TYPES_H__ */