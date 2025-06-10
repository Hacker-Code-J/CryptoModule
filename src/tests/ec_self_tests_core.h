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
#ifndef __EC_SELF_TESTS_CORE_H__
#define __EC_SELF_TESTS_CORE_H__

#include <crypto/cryptosig.h>

/* A test is fully defined by the attributes pointed in this structure. */
typedef struct {
	/* Test case name */
	const char *name;

	/* Curve params */
	const ec_str_params *ec_str_p;

	/* Private key */
	const u8 *priv_key;
	u8 priv_key_len;

	/* Function returning a fixed random value */
	int (*nn_random) (nn_t out, nn_src_t q);

	/* Hash function */
	hash_alg_type hash_type;

	/* Message */
	const char *msg;
	u32 msglen;

	/* Expected signature and associated length */
	ec_alg_type sig_type;
	const u8 *exp_sig;
	u8 exp_siglen;

	/* Optional ancillary data */
	const u8 *adata;
	u16 adata_len;
} ec_test_case;

/* ECDH test case */
typedef struct {
	/* Test case name */
	const char *name;

	/* ECDH type */
	ec_alg_type ecdh_type;

	/* Curve params */
	const ec_str_params *ec_str_p;

	/* Our private key */
	const u8 *our_priv_key;
	u8 our_priv_key_len;

	/* Peer public key */
	const u8 *peer_pub_key;
	u8 peer_pub_key_len;

	/* Our expected public key */
	const u8 *exp_our_pub_key;
	u8 exp_our_pub_key_len;

	/* Expected shared secret */
	const u8 *exp_shared_secret;
	u8 exp_shared_secret_len;
} ecdh_test_case;

/*******************************************************************
 ************** ECDSA tests ****************************************
 *******************************************************************/
#if (defined(HASH_SHA3_224) || defined(HASH_SHA3_256) || \
     defined(HASH_SHA3_384) || defined(HASH_SHA3_512))

/*
 * This test message is the 1600 bits message used by NIST in its
 * test vectors for SHA3. We reuse it for sig/verif test vectors
 * using SHA3.
 */
static const u8 sha3_1600_bit_msg[] = {
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3
};
#endif

#ifdef SIG_ECDSA

#ifdef HASH_SHA3_256
#ifdef CURVE_SECP256R1
#define ECDSA_SHA3_256_SECP256R1_SELF_TEST

/* ECDSA secp256r1 test vectors */

static int ecdsa_nn_random_secp256r1_sha3_256_test_vector(nn_t out, nn_src_t q)
{
	int ret, cmp;

	/*
	 * Fixed ephemeral private key for secp256r1 signature
	 * test vectors from RFC4754
	 */
	const u8 k_buf[] = {
		0x9E, 0x56, 0xF5, 0x09, 0x19, 0x67, 0x84, 0xD9,
		0x63, 0xD1, 0xC0, 0xA4, 0x01, 0x51, 0x0E, 0xE7,
		0xAD, 0xA3, 0xDC, 0xC5, 0xDE, 0xE0, 0x4B, 0x15,
		0x4B, 0xF6, 0x1A, 0xF1, 0xD5, 0xA6, 0xDE, 0xCE
	};

	ret = nn_init_from_buf(out, k_buf, sizeof(k_buf)); EG(ret, err);
	ret = nn_cmp(out, q, &cmp); EG(ret, err);

	ret = (cmp >= 0) ? -1 : 0;

err:
	return ret;
}

static const u8 ecdsa_secp256r1_sha3_256_test_vectors_priv_key[] = {
	0xDC, 0x51, 0xD3, 0x86, 0x6A, 0x15, 0xBA, 0xCD,
	0xE3, 0x3D, 0x96, 0xF9, 0x92, 0xFC, 0xA9, 0x9D,
	0xA7, 0xE6, 0xEF, 0x09, 0x34, 0xE7, 0x09, 0x75,
	0x59, 0xC2, 0x7F, 0x16, 0x14, 0xC8, 0x8A, 0x7F
};

static const u8 ecdsa_secp256r1_sha3_256_test_vectors_expected_sig[] = {
	0xCB, 0x28, 0xE0, 0x99, 0x9B, 0x9C, 0x77, 0x15,
	0xFD, 0x0A, 0x80, 0xD8, 0xE4, 0x7A, 0x77, 0x07,
	0x97, 0x16, 0xCB, 0xBF, 0x91, 0x7D, 0xD7, 0x2E,
	0x97, 0x56, 0x6E, 0xA1, 0xC0, 0x66, 0x95, 0x7C,

	0x1d, 0x5d, 0x46, 0x09, 0xa2, 0xf9, 0x69, 0xa1,
	0x90, 0xeb, 0x6b, 0x84, 0x51, 0xdd, 0x43, 0x0d,
	0x65, 0x07, 0x10, 0x4d, 0xb6, 0x46, 0x61, 0x68,
	0xec, 0x7a, 0x73, 0xdb, 0x8c, 0x96, 0xe9, 0x1b
};

static const ec_test_case ecdsa_secp256r1_sha3_256_test_case = {
	.name = "ECDSA-SHA3_256/secp256r1",
	.ec_str_p = &secp256r1_str_params,
	.priv_key = ecdsa_secp256r1_sha3_256_test_vectors_priv_key,
	.priv_key_len = sizeof(ecdsa_secp256r1_sha3_256_test_vectors_priv_key),
	.nn_random = ecdsa_nn_random_secp256r1_sha3_256_test_vector,
	.hash_type = SHA3_256,
	.msg = (const char *)sha3_1600_bit_msg,
	.msglen = sizeof(sha3_1600_bit_msg),
	.sig_type = ECDSA,
	.exp_sig = ecdsa_secp256r1_sha3_256_test_vectors_expected_sig,
	.exp_siglen =
		sizeof(ecdsa_secp256r1_sha3_256_test_vectors_expected_sig),
	.adata = NULL,
	.adata_len = 0
};
#endif /* CURVE_SECP256R1 */
#endif /* HASH_SHA3_256 */

#ifdef HASH_SHA256
#ifdef CURVE_SECP256R1
#define ECDSA_SHA256_SECP256R1_SELF_TEST

/* ECDSA secp256r1 test vectors */

static int ecdsa_nn_random_rfc4754_secp256r1_test_vector(nn_t out, nn_src_t q)
{
	int ret, cmp;

	/*
	 * Fixed ephemeral private key for secp256r1 signature
	 * test vectors from RFC4754
	 */
	const u8 k_buf[] = {
		0x9E, 0x56, 0xF5, 0x09, 0x19, 0x67, 0x84, 0xD9,
		0x63, 0xD1, 0xC0, 0xA4, 0x01, 0x51, 0x0E, 0xE7,
		0xAD, 0xA3, 0xDC, 0xC5, 0xDE, 0xE0, 0x4B, 0x15,
		0x4B, 0xF6, 0x1A, 0xF1, 0xD5, 0xA6, 0xDE, 0xCE
	};

	ret = nn_init_from_buf(out, k_buf, sizeof(k_buf)); EG(ret, err);
	ret = nn_cmp(out, q, &cmp); EG(ret, err);

	ret = (cmp >= 0) ? -1 : 0;

err:
	return ret;
}

static const u8 ecdsa_secp256r1_test_vectors_priv_key[] = {
	0xDC, 0x51, 0xD3, 0x86, 0x6A, 0x15, 0xBA, 0xCD,
	0xE3, 0x3D, 0x96, 0xF9, 0x92, 0xFC, 0xA9, 0x9D,
	0xA7, 0xE6, 0xEF, 0x09, 0x34, 0xE7, 0x09, 0x75,
	0x59, 0xC2, 0x7F, 0x16, 0x14, 0xC8, 0x8A, 0x7F
};

static const u8 ecdsa_secp256r1_test_vectors_expected_sig[] = {
	0xCB, 0x28, 0xE0, 0x99, 0x9B, 0x9C, 0x77, 0x15,
	0xFD, 0x0A, 0x80, 0xD8, 0xE4, 0x7A, 0x77, 0x07,
	0x97, 0x16, 0xCB, 0xBF, 0x91, 0x7D, 0xD7, 0x2E,
	0x97, 0x56, 0x6E, 0xA1, 0xC0, 0x66, 0x95, 0x7C,
	0x86, 0xFA, 0x3B, 0xB4, 0xE2, 0x6C, 0xAD, 0x5B,
	0xF9, 0x0B, 0x7F, 0x81, 0x89, 0x92, 0x56, 0xCE,
	0x75, 0x94, 0xBB, 0x1E, 0xA0, 0xC8, 0x92, 0x12,
	0x74, 0x8B, 0xFF, 0x3B, 0x3D, 0x5B, 0x03, 0x15
};

static const ec_test_case ecdsa_secp256r1_test_case = {
	.name = "ECDSA-SHA256/secp256r1",
	.ec_str_p = &secp256r1_str_params,
	.priv_key = ecdsa_secp256r1_test_vectors_priv_key,
	.priv_key_len = sizeof(ecdsa_secp256r1_test_vectors_priv_key),
	.nn_random = ecdsa_nn_random_rfc4754_secp256r1_test_vector,
	.hash_type = SHA256,
	.msg = "abc",
	.msglen = 3,
	.sig_type = ECDSA,
	.exp_sig = ecdsa_secp256r1_test_vectors_expected_sig,
	.exp_siglen = sizeof(ecdsa_secp256r1_test_vectors_expected_sig),
	.adata = NULL,
	.adata_len = 0
};
#endif /* CURVE_SECP256R1 */
#endif /* HASH_SHA256 */

#endif /* SIG_ECDSA */

/* ADD curve test vectors header here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */

/* Dummy empty test case to avoid empty array
 * when no test case is defined
 */
static const ec_test_case dummy_test_case = {
	.name = "Dummy SIGN",
	.ec_str_p = NULL,
	.priv_key = NULL,
	.priv_key_len = 0,
	.nn_random = NULL,
	.hash_type = UNKNOWN_HASH_ALG,
	.msg = NULL,
	.msglen = 0,
	.sig_type = UNKNOWN_ALG,
	.exp_sig = NULL,
	.exp_siglen = 0,
	.adata = NULL,
	.adata_len = 0
};

/* List of all test cases */

static const ec_test_case *ec_fixed_vector_tests[] = {
	/* ECDSA */
#ifdef ECDSA_SHA256_SECP256R1_SELF_TEST
	&ecdsa_secp256r1_test_case,
#endif
#ifdef ECDSA_SHA3_256_SECP256R1_SELF_TEST
	&ecdsa_secp256r1_sha3_256_test_case,
#endif
	/* Dummy empty test case to avoid empty array
	 * when no test case is defined */
	&dummy_test_case,

/* ADD curve test case here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */
};

#define EC_FIXED_VECTOR_NUM_TESTS \
	(sizeof(ec_fixed_vector_tests) / sizeof(ec_fixed_vector_tests[0]))


/* Dummy empty test case to avoid empty array
 * when no test case is defined
 */
static const ecdh_test_case ecdh_dummy_test_case = {
	.name = "Dummy ECDH",
	.ecdh_type = UNKNOWN_ALG,
	.ec_str_p = NULL,
	.our_priv_key = NULL,
	.our_priv_key_len = 0,
	.peer_pub_key = NULL,
	.peer_pub_key_len = 0,
	.exp_our_pub_key = NULL,
	.exp_our_pub_key_len = 0,
	.exp_shared_secret = NULL,
	.exp_shared_secret_len = 0,
};

#define ECDH_FIXED_VECTOR_NUM_TESTS \
        (sizeof(ecdh_fixed_vector_tests) / sizeof(ecdh_fixed_vector_tests[0]))

/*
 * A fixed test can fail in various ways. The way we report the failure
 * to the caller is by returning a non-zero value, in which we encode
 * some informations on the failure: curve, sig alg, hash alg, operation
 * (key import, signature, sig comparison, verification). Those 4 pieces
 * of information are each encoded on 8 bits in that order on the 28 LSB
 * of the return value. The function below produces a meaningful negative
 * return value in that specific format.
 */
typedef enum {
	TEST_KEY_IMPORT_ERROR = 1,
	TEST_SIG_ERROR = 2,
	TEST_SIG_COMP_ERROR = 3,
	TEST_VERIF_ERROR = 4,
	TEST_ECDH_ERROR = 5,
	TEST_ECDH_COMP_ERROR = 6,
} test_err_kind;

static int encode_error_value(const ec_test_case *c, test_err_kind failed_test, u32 *err_val)
{
	ec_curve_type ctype;
	ec_alg_type stype = c->sig_type;
	hash_alg_type htype = c->hash_type;
	test_err_kind etype = failed_test;
	int ret;

	MUST_HAVE((c != NULL) && (err_val != NULL), ret, err);

	ret = ec_get_curve_type_by_name(c->ec_str_p->name->buf,
					c->ec_str_p->name->buflen, &ctype); EG(ret, err);

	*err_val = (((u32)ctype << 24) |
		    ((u32)stype << 16) |
		    ((u32)htype <<  8) |
		    ((u32)etype));
	ret = 0;

err:
	return ret;
}

static inline int ecdh_encode_error_value(const ecdh_test_case *c, test_err_kind failed_test, u32 *err_val)
{
	ec_curve_type ctype;
	ec_alg_type stype = c->ecdh_type;
	test_err_kind etype = failed_test;
	int ret;

	MUST_HAVE((c != NULL) && (err_val != NULL), ret, err);

	ret = ec_get_curve_type_by_name(c->ec_str_p->name->buf,
					c->ec_str_p->name->buflen, &ctype); EG(ret, err);

	*err_val = (((u32)ctype << 24) |
		    ((u32)stype << 16) |
		    ((u32)0 <<  8) |
		    ((u32)etype));
	ret = 0;

err:
	return ret;
}

int perform_known_test_vectors_test(const char *sig, const char *hash, const char *curve);
int perform_random_sig_verif_test(const char *sig, const char *hash, const char *curve);
int perform_performance_test(const char *sig, const char *hash, const char *curve);

#endif /* __EC_SELF_TESTS_CORE_H__ */
