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
#ifndef __CRYPTO_ECC_CONFIG_H__
#define __CRYPTO_ECC_CONFIG_H__

/*
 * This configuration file provides various knobs to configure
 * what will be built in the library (supported curves, hash
 * algorithms and signature/verification schemes).
 */

/* It is possible to override the LIBECC configuration by defining
 * the LIBECC_CONFIG_OVERRIDE preprocessing flag in the CFLAGS. When
 * this is done, it is expected that the user defines the curves,
 * hash algorithms and signature schemes in the compilation
 * command line (e.g. via the CFLAGS).
 * For instance, in order to only use FRP256V1, SHA-256 and ECDSA, add to the CFLAGS:
 *
 *   -DLIBECC_CONFIG_OVERRIDE -DCURVE_FRP256V1 -DHASH_SHA256 -DSIG_ECDSA
 *
 */

/* Supported curves */
#define CURVE_SECP256R1
/* ADD curves define here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */

/* Supported hash algorithms */
#define HASH_SHA256
#define HASH_SHA3_256
#define HASH_SHAKE256
#define HMAC

/* Supported sig/verif schemes */
#define SIG_ECDSA

// /* Supported ECDH schemes */
// #define ECCCDH
// #define X25519

#endif /* __CRYPTO_ECC_CONFIG_H__ */
