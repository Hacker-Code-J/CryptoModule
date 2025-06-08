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
#ifndef __CURVES_LIST_H__
#define __CURVES_LIST_H__

#include <crypto/crypto_ecc_config.h>
#include <crypto/crypto_ecc_types.h>
#include <crypto/words/words.h>
#include <crypto/curves/ec_params_secp256r1.h>
/* ADD curves header here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */

#ifndef CURVES_MAX_P_BIT_LEN
#error "Max p bit length is 0; did you disable all curves in lib_ecc_config.h?"
#endif
#if (CURVES_MAX_P_BIT_LEN > 65535)
#error "Prime field length (in bytes) MUST fit on an u16!"
#endif

#ifndef CURVES_MAX_Q_BIT_LEN
#error "Max q bit length is 0; did you disable all curves in lib_ecc_config.h?"
#endif
#if (CURVES_MAX_Q_BIT_LEN > 65535)
#error "Generator order length (in bytes) MUST fit on an u16!"
#endif

#ifndef CURVES_MAX_CURVE_ORDER_BIT_LEN
#error "Max curve order bit length is 0; did you disable all curves in lib_ecc_config.h?"
#endif
#if (CURVES_MAX_CURVE_ORDER_BIT_LEN > 65535)
#error "Curve order length (in bytes) MUST fit on an u16!"
#endif

typedef struct {
	ec_curve_type type;
	const ec_str_params *params;
} ec_mapping;

static const ec_mapping ec_maps[] = {
#ifdef CURVE_FRP256V1
	{.type = FRP256V1,.params = &frp256v1_str_params},
#endif /* CURVE_FRP256V1 */
#ifdef CURVE_SECP192R1
	{.type = SECP192R1,.params = &secp192r1_str_params},
#endif /* CURVE_SECP192R1 */
#ifdef CURVE_SECP224R1
	{.type = SECP224R1,.params = &secp224r1_str_params},
#endif /* CURVE_SECP224R1 */
#ifdef CURVE_SECP256R1
	{.type = SECP256R1,.params = &secp256r1_str_params},
#endif /* CURVE_SECP256R1 */
/* ADD curves mapping here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */
};

/*
 * Number of cuvres supported by the lib, i.e. number of elements in
 * ec_maps array above.
 */
#define EC_CURVES_NUM (sizeof(ec_maps) / sizeof(ec_mapping))
#endif /* __CURVES_LIST_H__ */
