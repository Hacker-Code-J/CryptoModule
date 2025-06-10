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
#include <crypto/utils/utils.h>
#include <crypto/external_deps/rand.h>
#include <crypto/external_deps/time.h>
#include <crypto/external_deps/print.h>
#include "ec_self_tests_core.h"

#define OPENMP_LOCK()
#define OPENMP_UNLOCK()
#define OPENMP_EG(ret, err) do {				  \
	EG(ret, err);						  \
} while(0)

static int ec_gen_import_export_kp(ec_key_pair *kp, const ec_params *params,
				   const ec_test_case *c)
{
	u8 pub_key_buf[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
	u8 priv_key_buf[EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE];
	u8 pub_key_buf_len, priv_key_buf_len;
	ec_key_pair imported_kp;
	int ret;

	MUST_HAVE(c != NULL, ret, err);

	ret = local_memset(pub_key_buf, 0, sizeof(pub_key_buf)); EG(ret, err);
	ret = local_memset(priv_key_buf, 0, sizeof(priv_key_buf)); EG(ret, err);
	ret = local_memset(&imported_kp, 0, sizeof(imported_kp)); EG(ret, err);

	/* Generate key pair */
	ret = ec_key_pair_gen(kp, params, c->sig_type);
	if (ret) {
		ext_printf("Error generating key pair\n");
		goto err;
	}
	pub_key_buf_len = EC_STRUCTURED_PUB_KEY_EXPORT_SIZE(&(kp->pub_key));
	priv_key_buf_len = EC_STRUCTURED_PRIV_KEY_EXPORT_SIZE(&(kp->priv_key));

	/* Export public and private keys in buffers */
	ret = ec_structured_pub_key_export_to_buf(&(kp->pub_key), pub_key_buf,
					  pub_key_buf_len);
	if (ret) {
		ext_printf("Error exporting public key\n");
		goto err;
	}
	ret = ec_structured_priv_key_export_to_buf(&(kp->priv_key),
					   priv_key_buf,
					   priv_key_buf_len);
	if (ret) {
		ext_printf("Error exporting private key\n");
		goto err;
	}

	/* Import public and private key */
	ret = ec_structured_pub_key_import_from_buf(&(imported_kp.pub_key),
					    params,
					    pub_key_buf,
					    pub_key_buf_len,
					    c->sig_type);
	if (ret) {
		ext_printf("Error importing public key\n");
		goto err;
	}
	ret = ec_structured_priv_key_import_from_buf(&(imported_kp.priv_key),
					     params, priv_key_buf,
					     priv_key_buf_len,
					     c->sig_type);
	if (ret) {
		ext_printf("Error importing private key\n");
		goto err;
	}
	ret = 0;

err:
	return ret;
}

/* This function randomly splits the message input in small chunks to
 * test the signature init / multiple updates / finalize mechanism for
 * algorithms that support them.
 */
static int random_split_ec_sign(u8 *sig, u8 siglen, const ec_key_pair *key_pair,
	     const u8 *m, u32 mlen,
	     int (*rand) (nn_t out, nn_src_t q),
	     ec_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len)
{
	struct ec_sign_context ctx;
	int ret;
	u32 consumed;

	ret = local_memset(&ctx, 0, sizeof(ctx)); EG(ret, err);

	MUST_HAVE(sig != NULL, ret, err);
	MUST_HAVE(key_pair != NULL, ret, err);
	MUST_HAVE(m != NULL, ret, err);
	/* note: adata == NULL is allowed */

	ret = _ec_sign_init(&ctx, key_pair, rand, sig_type, hash_type, adata, adata_len);
	if (ret) {
		goto err;
	}
	/* We randomly split the input message in chunks and proceed with updates */
	consumed = 0;
	while(consumed < mlen){
		u32 toconsume = 0;
		ret = get_random((u8 *)&toconsume, sizeof(toconsume));
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}
		toconsume = (toconsume % (mlen - consumed));
		if(((mlen - consumed) == 1) && (toconsume == 0)){
			toconsume = 1;
		}
		ret = ec_sign_update(&ctx, &m[consumed], toconsume);
		if (ret) {
			goto err;
		}
		consumed += toconsume;
	}

	ret = ec_sign_finalize(&ctx, sig, siglen);

 err:
	return ret;
}

/* This function randomly splits the message input in small chunks to
 * test the verification init / multiple updates / finalize mechanism for
 * algorithms that support them.
 */
static int random_split_ec_verify(const u8 *sig, u8 siglen, const ec_pub_key *pub_key,
	      const u8 *m, u32 mlen,
	      ec_alg_type sig_type, hash_alg_type hash_type, const u8 *adata, u16 adata_len)
{
	int ret;
	struct ec_verify_context ctx;
	u32 consumed;

	ret = local_memset(&ctx, 0, sizeof(ctx)); EG(ret, err);

	ret = ec_verify_init(&ctx, pub_key, sig, siglen, sig_type, hash_type, adata, adata_len);
	if (ret) {
		goto err;
	}

	/* We randomly split the input message in chunks and proceed with updates */
	consumed = 0;
	while(consumed < mlen){
		u32 toconsume = 0;
		ret = get_random((u8 *)&toconsume, sizeof(toconsume));
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}
		toconsume = (toconsume % (mlen - consumed));
		if(((mlen - consumed) == 1) && (toconsume == 0)){
			toconsume = 1;
		}
		ret = ec_verify_update(&ctx, &m[consumed], toconsume);
		if (ret) {
			goto err;
		}
		consumed += toconsume;
	}

	ret = ec_verify_finalize(&ctx);

 err:
	return ret;
}


/* Reduce pressure on the stack for small targets
 * by letting the user override this value.
 */
#ifndef MAX_MSG_LEN
#if WORDSIZE == 16
/* For wordsize 16 bits, avoid overflows */
#define MAX_MSG_LEN 1024
#else
#define MAX_MSG_LEN 8192
#endif
#endif
#ifndef MAX_BATCH_SIG_SIZE
#define MAX_BATCH_SIG_SIZE 20
#endif

/*
 * ECC generic self tests (sign/verify on random values
 * with import/export)
 */
static int ec_import_export_test(const ec_test_case *c)
{
	ec_key_pair kp;
	ec_params params;
	int ret, check;

	MUST_HAVE(c != NULL, ret, err);

	ret = local_memset(&kp, 0, sizeof(kp)); EG(ret, err);
	ret = local_memset(&params, 0, sizeof(params)); EG(ret, err);

	/* Import EC params from test case */
	ret = import_params(&params, c->ec_str_p);
	if (ret) {
		ext_printf("Error importing params\n");
		goto err;
	}

	/* Generate, import/export a key pair */
	ret = ec_gen_import_export_kp(&kp, &params, c);
	if (ret) {
		ext_printf("Error at key pair generation/import/export\n");
		goto err;
	}

	/* Perform test */
	{
		u16 msglen;
		u8 siglen;
		u8 msg[MAX_MSG_LEN];
		u8 sig[EC_MAX_SIGLEN];
		u8 check_type = 0;
		u8 sig_tmp1[EC_MAX_SIGLEN];
		u8 sig_tmp2[EC_MAX_SIGLEN];
		FORCE_USED_VAR(check_type);

		ret = ec_get_sig_len(&params, c->sig_type, c->hash_type,
				     (u8 *)&siglen);
		if (ret) {
			ext_printf("Error computing effective sig size\n");
			goto err;
		}

		/* Generate a random message to sign */
		ret = get_random((u8 *)&msglen, sizeof(msglen));
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}
		msglen = msglen % MAX_MSG_LEN;
		ret = get_random(msg, msglen);
		if (ret) {
			ext_printf("Error when getting random\n");
			goto err;
		}

		ret = _ec_sign(sig, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
		if (ret) {
			ext_printf("Error when signing\n");
			goto err;
		}
		ret = local_memset(sig_tmp1, 0, sizeof(sig_tmp1)); EG(ret, err);
		ret = local_memset(sig_tmp2, 0, sizeof(sig_tmp2)); EG(ret, err);
		/* If the algorithm supports streaming mode, test it against direct mode */
		ret = is_sign_streaming_mode_supported(c->sig_type, &check); EG(ret, err);
		if(check){
			MUST_HAVE(siglen <= LOCAL_MAX(sizeof(sig_tmp1), sizeof(sig_tmp2)), ret, err);
			ret = generic_ec_sign(sig_tmp1, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
			if(ret){
				ext_printf("Error when signing\n");
				ret = -1;
				goto err;
			}
			ret = random_split_ec_sign(sig_tmp2, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
			if(ret){
				ext_printf("Error when signing\n");
				ret = -1;
				goto err;
			}
			/* Verify signature equality only in case of deterministic signatures */
			ret = is_sign_deterministic(c->sig_type, &check); EG(ret, err);
			if(check){
				ret = are_equal(sig, sig_tmp1, siglen, &check); EG(ret, err);
				if(!check){
					ext_printf("Error when signing: streaming and non streaming modes results differ "\
						   "for deterministic signature scheme!\n");
					ret = -1;
					goto err;
				}
				ret = are_equal(sig, sig_tmp2, siglen, &check); EG(ret, err);
				if(!check){
					ext_printf("Error when signing: streaming and non streaming modes results differ "\
						   "for deterministic signature scheme!\n");
					ret = -1;
					goto err;
				}
			}
		}

		ret = ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
				c->sig_type, c->hash_type, c->adata, c->adata_len);
		if (ret) {
			ext_printf("Error when verifying signature\n");
			goto err;
		}
		/* If the algorithm supports streaming mode, test it against direct mode */
		ret = is_verify_streaming_mode_supported(c->sig_type, &check); EG(ret, err);
		if(check){
			ret = is_sign_streaming_mode_supported(c->sig_type, &check); EG(ret, err);
			if(check){
				ret = ec_verify(sig_tmp2, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			}
			else{
				ret = ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			}
			if (ret) {
				ext_printf("Error when verifying signature ec_verify\n");
				goto err;
			}
			ret = is_sign_streaming_mode_supported(c->sig_type, &check); EG(ret, err);
			if(check){
				ret = random_split_ec_verify(sig_tmp1, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			}
			else{
				ret = random_split_ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			}
			if (ret) {
				ext_printf("Error when verifying signature random_split_ec_verify\n");
				goto err;
			}
		}
		/* Also test the "single" signature batch verification */
		ret = is_verify_batch_mode_supported(c->sig_type, &check); EG(ret, err);
		if(check){
			const u8 *signatures[] = { sig };
			const u8 signatures_len[] = { siglen };
			const u8 *messages[] = { msg };
			const u32 messages_len[] = { msglen };
			const ec_pub_key *pub_keys[] = { &(kp.pub_key) };
			const u8 *adatas[] = { c->adata };
			const u16 adatas_len[] = { c->adata_len };
			ret = ec_verify_batch(signatures, signatures_len, pub_keys, messages, messages_len,
					1, c->sig_type, c->hash_type, adatas, adatas_len, NULL, NULL);
			if(ret){
				ext_printf("Error when verifying signature ec_verify_batch with batch 1\n");
				goto err;
			}
		}
		check_type = 0;
#if defined(SIG_ECDSA)
		if(c->sig_type == ECDSA){
			check_type = 1;
		}
#endif
		/* Try a public key recovery from the signature and the message.
		 * This is only possible for ECDSA.
		 */
		if(check_type){
			struct ec_sign_context sig_ctx;
			u8 digest[MAX_DIGEST_SIZE] = { 0 };
			u8 digestlen;
			ec_pub_key pub_key1;
			ec_pub_key pub_key2;
			nn_src_t cofactor = &(params.ec_gen_cofactor);
			int cofactorisone;
			const u8 *input[2] = { (const u8*)msg , NULL};
			u32 ilens[2] = { msglen , 0 };
			/* Initialize our signature context only for the hash */
			ret = ec_sign_init(&sig_ctx, &kp, c->sig_type, c->hash_type, c->adata, c->adata_len); EG(ret, err);
			/* Perform the hash of the data ourselves */
			ret = hash_mapping_callbacks_sanity_check(sig_ctx.h); EG(ret, err);
			ret = sig_ctx.h->hfunc_scattered(input, ilens, digest); EG(ret, err);
			digestlen = sig_ctx.h->digest_size;
			MUST_HAVE(digestlen <= sizeof(digest), ret, err);
			/* Check the cofactor */
			ret = nn_isone(cofactor, &cofactorisone); EG(ret, err);
			/* Compute the two possible public keys */
			ret = __ecdsa_public_key_from_sig(&pub_key1, &pub_key2, &params, sig, siglen, digest, digestlen, c->sig_type);
			if(ret){
				ret = 0;
				check = -1;
				goto pubkey_recovery_warning;
			}
			/* Check equality with one of the two keys */
			ret = prj_pt_cmp(&(pub_key1.y), &(kp.pub_key.y), &check); EG(ret, err);
			if(check){
				ret = prj_pt_cmp(&(pub_key2.y), &(kp.pub_key.y), &check); EG(ret, err);
			}
pubkey_recovery_warning:
			if(check && cofactorisone){
				OPENMP_LOCK();
				ext_printf("[~] Warning: ECDSA recovered public key differs from real one ...");
				ext_printf("This can happen with very low probability. Please check the trace:\n");
				pub_key_print("pub_key1", &pub_key1);
				pub_key_print("pub_key2", &pub_key2);
				pub_key_print("pub_key", &(kp.pub_key));
				buf_print("digest", digest, digestlen);
				buf_print("sig", sig, siglen);
				OPENMP_UNLOCK();
			}
		}
	}

	/* Perform test specific to batch verification */
	ret = is_verify_batch_mode_supported(c->sig_type, &check); EG(ret, err);
	if(check){
		u16 msglen;
		u8 siglen;
		ec_key_pair keypairs[MAX_BATCH_SIG_SIZE];
		const ec_pub_key *pubkeys[MAX_BATCH_SIG_SIZE];
		u8 msg[MAX_BATCH_SIG_SIZE * MAX_MSG_LEN];
		const u8 *messages[MAX_BATCH_SIG_SIZE];
		u32 messages_len[MAX_BATCH_SIG_SIZE];
		u8 sig[MAX_BATCH_SIG_SIZE * EC_MAX_SIGLEN];
		const u8 *signatures[MAX_BATCH_SIG_SIZE];
		u8 signatures_len[MAX_BATCH_SIG_SIZE];
		const u8 *adata[MAX_BATCH_SIG_SIZE];
		u16 adata_len[MAX_BATCH_SIG_SIZE];
		u8 check_type = 0;
		u32 num_batch, i, current;

		FORCE_USED_VAR(check_type);

gen_num_batch:
		ret = get_random((u8 *)&num_batch, sizeof(num_batch));
		if(ret){
			ext_printf("Error when getting random\n");
			goto err;
		}
		num_batch = (num_batch % MAX_BATCH_SIG_SIZE);
		if(num_batch == 0){
			goto gen_num_batch;
		}

		ret = ec_get_sig_len(&params, c->sig_type, c->hash_type,
				     (u8 *)&siglen);
		if (ret) {
			ext_printf("Error computing effective sig size\n");
			goto err;
		}

		/* Generate random messages to sign */
		current = 0;
		for(i = 0; i < num_batch; i++){
			/* Generate, import/export a key pair */
			ret = ec_gen_import_export_kp(&keypairs[i], &params, c);
			pubkeys[i] = &(keypairs[i].pub_key);
			if (ret) {
				ext_printf("Error at key pair generation/import/export\n");
				goto err;
			}
			ret = get_random((u8 *)&msglen, sizeof(msglen));
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}
			msglen = msglen % MAX_MSG_LEN;
			messages_len[i] = msglen;
			messages[i] = &msg[current];
			ret = get_random(&msg[current], msglen);
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}
			current += msglen;

			signatures[i] = &sig[i * siglen];
			signatures_len[i] = siglen;
			adata_len[i] = c->adata_len;
			adata[i] = c->adata;
			ret = _ec_sign(&sig[i * siglen], siglen, &keypairs[i], messages[i], messages_len[i],
				       c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
			if (ret) {
				ext_printf("Error when signing\n");
				goto err;
			}
		}
		/* Test */
		ret = ec_verify_batch(signatures, signatures_len, pubkeys, messages, messages_len,
				num_batch, c->sig_type, c->hash_type, adata, adata_len, NULL, NULL);
		if(ret){
			ext_printf("Error when verifying signature ec_verify_batch no memory for batch size %" PRIu32 "\n", num_batch);
			goto err;
		}
		{
			u32 scratch_pad_area_len = 0;
			/* We need 2 * n + 1 scratch pad storage, compute this with max */
			verify_batch_scratch_pad scratch_pad_area[(2 * MAX_BATCH_SIG_SIZE) + 1];

			ret = ec_verify_batch(signatures, signatures_len, pubkeys, messages, messages_len,
					num_batch, c->sig_type, c->hash_type, adata, adata_len, NULL, &scratch_pad_area_len);
			if(ret){
				ext_printf("Error when getting scratch_pad_area length for ec_verify_batch optimized  for batch size %" PRIu32 "\n", num_batch);
				goto err;
			}
			MUST_HAVE((scratch_pad_area_len <= sizeof(scratch_pad_area)), ret, err);

			scratch_pad_area_len = sizeof(scratch_pad_area);
			ret = ec_verify_batch(signatures, signatures_len, pubkeys, messages, messages_len,
					num_batch, c->sig_type, c->hash_type, adata, adata_len, scratch_pad_area, &scratch_pad_area_len);
			if(ret){
				ext_printf("Error when verifying signature ec_verify_batch optimized for batch size %" PRIu32 "\n", num_batch);
				goto err;
			}
		}
	}

	ret = 0;

 err:
	return ret;
}

/*
 * Those functions respectively perform signature and verification tests
 * based the content of a given test case.
 */
static int ec_test_sign(u8 *sig, u8 siglen, ec_key_pair *kp,
			const ec_test_case *c)
{
	/* If the algorithm supports streaming, we check that both the streaming and
	 * non streaming modes produce the same result.
	 */
	int ret, check;

	MUST_HAVE(sig != NULL, ret, err);
	MUST_HAVE(c != NULL, ret, err);

	ret = _ec_sign(sig, siglen, kp, (const u8 *)(c->msg), c->msglen,
				c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len); EG(ret, err);
	ret = is_sign_streaming_mode_supported(c->sig_type, &check); EG(ret, err);
	if(check){
		u8 sig_tmp[EC_MAX_SIGLEN];
		MUST_HAVE(siglen <= sizeof(sig_tmp), ret, err);
		ret = generic_ec_sign(sig_tmp, siglen, kp, (const u8 *)(c->msg), c->msglen,
				c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len); EG(ret, err);
		ret = are_equal(sig, sig_tmp, siglen, &check); EG(ret, err);
		if(!check){
			ret = -1;
			goto err;
		}
		/* Now test the random split version */
		ret = random_split_ec_sign(sig_tmp, siglen, kp, (const u8 *)(c->msg), c->msglen,
				c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len); EG(ret, err);
		ret = are_equal(sig, sig_tmp, siglen, &check); EG(ret, err);
		if(!check){
			ret = -1;
			goto err;
		}
	}

	ret = 0;
err:
	return ret;
}

static int ec_test_verify(u8 *sig, u8 siglen, const ec_pub_key *pub_key,
			  const ec_test_case *c)
{
	/* If the algorithm supports streaming, we check that both the streaming and
	 * non streaming modes produce the same result.
	 */
	int ret, check;

	MUST_HAVE(sig != NULL, ret, err);
	MUST_HAVE(c != NULL, ret, err);

	ret = ec_verify(sig, siglen, pub_key, (const u8 *)(c->msg), c->msglen,
				 c->sig_type, c->hash_type, c->adata, c->adata_len);
	if(ret){
		ret = -1;
		goto err;
	}
	ret = is_verify_streaming_mode_supported(c->sig_type, &check); EG(ret, err);
	if(check){
		ret = ec_verify(sig, siglen, pub_key, (const u8 *)(c->msg), c->msglen,
				 c->sig_type, c->hash_type, c->adata, c->adata_len);
		if(ret){
			ret = -1;
			goto err;
		}
		/* Now test the random split version */
		ret = random_split_ec_verify(sig, siglen, pub_key, (const u8 *)(c->msg), c->msglen,
				 c->sig_type, c->hash_type, c->adata, c->adata_len);
		if(ret){
			ret = -1;
			goto err;
		}
	}
	/* Also test the "single" signature batch verification */
	ret = is_verify_batch_mode_supported(c->sig_type, &check); EG(ret, err);
	if(check){
		const u8 *signatures[] = { sig };
		const u8 signatures_len[] = { siglen };
		const u8 *messages[] = { (const u8*)c->msg };
		const u32 messages_len[] = { c->msglen };
		const ec_pub_key *pub_keys[] = { pub_key };
		const u8 *adatas[] = { c->adata };
		const u16 adatas_len[] = { c->adata_len };
		ret = ec_verify_batch(signatures, signatures_len, pub_keys, messages, messages_len,
				1, c->sig_type, c->hash_type, adatas, adatas_len, NULL, NULL);
		if(ret){
			ret = -1;
			goto err;
		}
	}

	ret = 0;
err:
	return ret;
}

/*
 * ECC generic self tests (sign/verify on known test vectors). Returns
 * 0 if given test succeeded, or a non-zero value otherwise. In that
 * case, the value encodes the information on what went wrong as
 * described above.
 */
static int ec_sig_known_vector_tests_one(const ec_test_case *c)
{
	test_err_kind failed_test = TEST_KEY_IMPORT_ERROR;
	u8 sig[EC_MAX_SIGLEN];
	ec_params params;
	ec_key_pair kp;
	u8 siglen;
	int ret;
	int check = 0;

	MUST_HAVE((c != NULL), ret, err);

	ret = local_memset(&kp, 0, sizeof(kp)); EG(ret, err);
	ret = local_memset(&params, 0, sizeof(params)); EG(ret, err);
	ret = local_memset(sig, 0, sizeof(sig)); EG(ret, err);

	ret = import_params(&params, c->ec_str_p);
	if (ret) {
		ext_printf("Error importing params\n");
		goto err;
	}

	{
		/* Regular import if not EdDSA */
		ret = ec_key_pair_import_from_priv_key_buf(&kp, &params, c->priv_key,
							   c->priv_key_len,
							   c->sig_type);
		if (ret) {
			failed_test = TEST_KEY_IMPORT_ERROR;
			goto err;
		}
	}

	siglen = c->exp_siglen;
	ret = ec_test_sign(sig, siglen, &kp, c);
	if (ret) {
		failed_test = TEST_SIG_ERROR;
		goto err;
	}

	ret = are_equal(sig, c->exp_sig, siglen, &check); EG(ret, err);
	if (!check) {
		ret = -1;
		failed_test = TEST_SIG_COMP_ERROR;
		goto err;
	}

	ret = ec_test_verify(sig, siglen, &(kp.pub_key), c);
	if (ret) {
		failed_test = TEST_VERIF_ERROR;
		goto err;
	}

	check = 0;
#if defined(SIG_ECDSA)
	if(c->sig_type == ECDSA){
		check = 1;
	}
#endif
	/* Try a public key recovery from the signature and the message.
	 * This is only possible for ECDSA.
	 */
	if(check){
		struct ec_sign_context sig_ctx;
		u8 digest[MAX_DIGEST_SIZE] = { 0 };
		u8 digestlen;
		ec_pub_key pub_key1;
		ec_pub_key pub_key2;
		nn_src_t cofactor = &(params.ec_gen_cofactor);
		int cofactorisone;
		const u8 *input[2] = { (const u8*)(c->msg) , NULL};
		u32 ilens[2] = { c->msglen , 0 };
		/* Initialize our signature context only for the hash */
		ret = ec_sign_init(&sig_ctx, &kp, c->sig_type, c->hash_type, c->adata, c->adata_len); EG(ret, err);
		/* Perform the hash of the data ourselves */
		ret = hash_mapping_callbacks_sanity_check(sig_ctx.h); EG(ret, err);
		ret = sig_ctx.h->hfunc_scattered(input, ilens, digest); EG(ret, err);
		digestlen = sig_ctx.h->digest_size;
		MUST_HAVE(digestlen <= sizeof(digest), ret, err);
		/* Check the cofactor */
		ret = nn_isone(cofactor, &cofactorisone); EG(ret, err);
		/* Compute the two possible public keys */
		ret = __ecdsa_public_key_from_sig(&pub_key1, &pub_key2, &params, sig, siglen, digest, digestlen, c->sig_type);
		if(ret){
			ret = 0;
			check = -1;
			goto pubkey_recovery_warning;
		}
		/* Check equality with one of the two keys */
		ret = prj_pt_cmp(&(pub_key1.y), &(kp.pub_key.y), &check); EG(ret, err);
		if(check){
			ret = prj_pt_cmp(&(pub_key2.y), &(kp.pub_key.y), &check); EG(ret, err);
		}
pubkey_recovery_warning:
		if(check && cofactorisone){
			OPENMP_LOCK();
			ext_printf("[~] Warning: ECDSA recovered public key differs from real one ...");
			ext_printf("This can happen with very low probability. Please check the trace:\n");
			pub_key_print("pub_key1", &pub_key1);
			pub_key_print("pub_key2", &pub_key2);
			pub_key_print("pub_key", &(kp.pub_key));
			buf_print("digest", digest, digestlen);
			buf_print("sig", sig, siglen);
			OPENMP_UNLOCK();
		}
	}

	ret = 0;

 err:
	if (ret) {
		u32 ret_;
		ret = encode_error_value(c, failed_test, &ret_); EG(ret, err);
		ret = (int)ret_;
	}

	return ret;
}

int perform_known_test_vectors_test(const char *sig, const char *hash, const char *curve)
{
	unsigned int i;
	int ret = 0;

	ext_printf("======= Known test vectors test =================\n");
#ifdef OPENMP_SELF_TESTS
        #pragma omp parallel
        #pragma omp for schedule(static, 1) nowait
#endif
	for (i = 0; i < EC_FIXED_VECTOR_NUM_TESTS; i++) {
		int check;
		const ec_test_case *cur_test;
		cur_test = ec_fixed_vector_tests[i];
		if(cur_test == NULL){
			continue;
		}
		/* If this is a dummy test case, skip it! */
		if(cur_test->sig_type == UNKNOWN_ALG){
			continue;
		}
		/* Filter out */
		if(sig != NULL){
			const ec_sig_mapping *sig_map;
			ret = get_sig_by_type(cur_test->sig_type, &sig_map); OPENMP_EG(ret, err);
			if(sig_map == NULL){
				continue;
			}
			ret = are_str_equal(sig_map->name, sig, &check); OPENMP_EG(ret, err);
			if(!check){
				continue;
			}
		}
		if(hash != NULL){
			const hash_mapping *hash_map;
			ret = get_hash_by_type(cur_test->hash_type, &hash_map); OPENMP_EG(ret, err);
			if(hash_map == NULL){
				continue;
			}
			ret = are_str_equal(hash_map->name, hash, &check); OPENMP_EG(ret, err);
			if(!check){
				continue;
			}
		}
		if(curve != NULL){
			if(cur_test->ec_str_p == NULL){
				continue;
			}
			ret = are_str_equal((const char*)cur_test->ec_str_p->name->buf, curve, &check); OPENMP_EG(ret, err);
			if(!check){
				continue;
			}
		}
		ret = ec_sig_known_vector_tests_one(cur_test);
		OPENMP_LOCK();
		ext_printf("[%s] %30s selftests: known test vectors "
			   "sig/verif %s\n", ret ? "-" : "+",
			   cur_test->name, ret ? "failed" : "ok");
		check = 0;
#if defined(SIG_ECDSA)
		if(cur_test->sig_type == ECDSA){
			check = 1;
		}
#endif
		if(check){
			ext_printf("\t(ECDSA public key recovery also checked!)\n");
		}
		OPENMP_UNLOCK();
		OPENMP_EG(ret, err);
	}

#ifndef OPENMP_SELF_TESTS
err:
#endif
	return ret;
}

static int rand_sig_verif_test_one(const ec_sig_mapping *sig,
				   const hash_mapping *hash,
				   const ec_mapping *ec)
{
	char test_name[MAX_CURVE_NAME_LEN + MAX_HASH_ALG_NAME_LEN +
		       MAX_SIG_ALG_NAME_LEN + 2];
	const unsigned int tn_size = sizeof(test_name) - 1; /* w/o trailing 0 */
	const char *crv_name;
	ec_test_case t;
	int ret, check;
	u32 len;

	ret = local_memset(test_name, 0, sizeof(test_name)); EG(ret, err);

	MUST_HAVE((sig != NULL), ret, err);
	MUST_HAVE((hash != NULL), ret, err);
	MUST_HAVE((ec != NULL), ret, err);

	crv_name  = (const char *)PARAM_BUF_PTR((ec->params)->name);

	/* Generate the test name */
	ret = local_memset(test_name, 0, tn_size + 1); EG(ret, err);
	ret = local_strncpy(test_name, sig->name, tn_size); EG(ret, err);
	ret = local_strlen(test_name, &len); EG(ret, err);
	ret = local_strncat(test_name, "-", tn_size - len); EG(ret, err);
	ret = local_strlen(test_name, &len); EG(ret, err);
	ret = local_strncat(test_name, hash->name, tn_size - len); EG(ret, err);
	ret = local_strlen(test_name, &len); EG(ret, err);
	ret = local_strncat(test_name, "/", tn_size - len); EG(ret, err);
	ret = local_strlen(test_name, &len); EG(ret, err);
	ret = local_strncat(test_name, crv_name, tn_size - len); EG(ret, err);

	/* Create a test */
	t.name = test_name;
	t.ec_str_p = ec->params;
	t.priv_key = NULL;
	t.priv_key_len = 0;
	t.nn_random = NULL;
	t.hash_type = hash->type;
	t.msg = NULL;
	t.msglen = 0;
	t.sig_type = sig->type;
	t.exp_sig = NULL;
	t.exp_siglen = 0;
	{
		{
			t.adata = NULL;
			t.adata_len = 0;
		}
	}

	/* Execute the test */
	ret = ec_import_export_test(&t);
	OPENMP_LOCK();
	ext_printf("[%s] %34s randtests: random import/export "
		   "with sig/verif %s\n", ret ? "-" : "+", t.name,
		   ret ? "failed" : "ok");
	check = 0;
#if defined(SIG_ECDSA)
	if(t.sig_type == ECDSA){
		check = 1;
	}
#endif
	if(check){
		ext_printf("\t(ECDSA public key recovery also checked!)\n");
	}

	OPENMP_UNLOCK();

err:
	return ret;
}

int perform_random_sig_verif_test(const char *sig, const char *hash, const char *curve)
{
	unsigned int num_sig_maps, num_hash_maps;
	int ret = 0;

	/* Compute number of sig and hash maps */
	for (num_sig_maps = 0; ec_sig_maps[num_sig_maps].type != UNKNOWN_ALG; num_sig_maps++) {}
	for (num_hash_maps = 0; hash_maps[num_hash_maps].type != UNKNOWN_HASH_ALG; num_hash_maps++) {}

	/*
	 * Perform basic sign/verify tests on all the cipher suites
	 * (combination of sign algo/hash function/curve)
	 */
	ext_printf("======= Random sig/verif test ===================\n");
	for (unsigned int i = 0; i < num_sig_maps; i++) {
#ifdef OPENMP_SELF_TESTS
		#pragma omp parallel for collapse(2)
#endif
		for (unsigned int j = 0; j < num_hash_maps; j++) {
			for (unsigned int k = 0; k < EC_CURVES_NUM; k++) {
				int check;
				if(sig != NULL){
					ret = are_str_equal(ec_sig_maps[i].name, sig, &check); OPENMP_EG(ret, err);
					if(!check){
						continue;
					}
				}
				if(hash != NULL){
					ret = are_str_equal(hash_maps[j].name, hash, &check); OPENMP_EG(ret, err);
					if(!check){
						continue;
					}
				}
				if(curve != NULL){
					ret = are_str_equal((const char*)ec_maps[k].params->name->buf, curve, &check); OPENMP_EG(ret, err);
					if(!check){
						continue;
					}
				}
				/* If we have EDDSA25519 or EDDSA448, we only accept specific hash functions.
				 * Skip the other tests.
				 */

				ret = rand_sig_verif_test_one(&ec_sig_maps[i],
							      &hash_maps[j],
							      &ec_maps[k]);
				OPENMP_EG(ret, err);
			}
		}
	}

#ifndef OPENMP_SELF_TESTS
err:
#endif
	return ret;
}

#define PERF_NUM_OP		300
#define PERF_BATCH_VERIFICATION 16

/*
 * ECC generic performance test: Returns the number of signatures
 * and verifications per second
 */
static int ec_performance_test(const ec_test_case *c,
			       unsigned int *n_perf_sign,
			       unsigned int *n_perf_verif,
			       unsigned int *n_perf_batch_verif,
			       unsigned char *batch_verify_ok)
{
	ec_key_pair kp;
	ec_params params;
	int ret, check;

	MUST_HAVE(c != NULL, ret, err);
	MUST_HAVE(n_perf_sign != NULL, ret, err);
	MUST_HAVE(n_perf_verif != NULL, ret, err);
	MUST_HAVE((n_perf_batch_verif != NULL) && (batch_verify_ok != NULL), ret, err);

	ret = local_memset(&kp, 0, sizeof(kp)); EG(ret, err);

	/* Import EC params from test case */
	ret = import_params(&params, c->ec_str_p);
	if (ret) {
		ext_printf("Error when importing parameters\n");
		goto err;
	}

	/* Generate, import/export a key pair */
	ret = ec_gen_import_export_kp(&kp, &params, c);
	if (ret) {
		ext_printf("Error at key pair generation/import/export\n");
		goto err;
	}

	/* Perform test */
	{
		u8 sig[EC_MAX_SIGLEN];
		u8 siglen;
		u8 msg[MAX_BLOCK_SIZE];
		u16 msglen;
		u8 hash_digest_size, hash_block_size;
		/* Time related variables */
		u64 time1, time2, cumulated_time_sign, cumulated_time_verify, cumulated_time_batch_verify;
		unsigned int i;

		ret = local_memset(sig, 0, sizeof(sig)); EG(ret, err);
		ret = local_memset(msg, 0, sizeof(msg)); EG(ret, err);

		ret = ec_get_sig_len(&params, c->sig_type, c->hash_type,
			     (u8 *)&siglen);
		if (ret) {
			ext_printf("Error computing effective sig size\n");
			goto err;
		}

		/*
		 * Random tests to measure performance: We do it on small
		 * messages to "absorb" the hash function cost
		 */
		ret = get_hash_sizes(c->hash_type, &hash_digest_size,
			     &hash_block_size);
		if (ret) {
			ext_printf("Error when getting hash size\n");
			goto err;
		}
		cumulated_time_sign = cumulated_time_verify = cumulated_time_batch_verify = 0;
		for (i = 0; i < PERF_NUM_OP; i++) {
			/* Generate a random message to sign */
			ret = get_random((u8 *)&msglen, sizeof(msglen));
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}
			msglen = (u16)(msglen % hash_block_size);
			ret = get_random(msg, msglen);
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}

			/***** Signature **********/
			ret = get_ms_time(&time1);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			ret = _ec_sign(sig, siglen, &kp, msg, msglen,
			       c->nn_random, c->sig_type, c->hash_type, c->adata, c->adata_len);
			if (ret) {
				ext_printf("Error when signing\n");
				goto err;
			}
			ret = get_ms_time(&time2);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			if (time2 < time1) {
				ext_printf("Error: time error (t2 < t1)\n");
				goto err;
			}
			cumulated_time_sign += (time2 - time1);

			/***** Verification **********/
			ret = get_ms_time(&time1);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			ret = ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
					c->sig_type, c->hash_type, c->adata, c->adata_len);
			if (ret) {
				ext_printf("Error when verifying signature\n");
				goto err;
			}
			ret = get_ms_time(&time2);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			if (time2 < time1) {
				ext_printf("Error: time error (time2 < time1)\n");
				goto err;
			}
			cumulated_time_verify += (time2 - time1);

			/***** Batch verification **********/
			ret = is_verify_batch_mode_supported(c->sig_type, &check); EG(ret, err);
			if(check){
				unsigned int j;
				const u8 *signatures[PERF_BATCH_VERIFICATION];
				u8 signatures_len[PERF_BATCH_VERIFICATION];
				const u8 *messages[PERF_BATCH_VERIFICATION];
				u32 messages_len[PERF_BATCH_VERIFICATION];
				const ec_pub_key *pub_keys[PERF_BATCH_VERIFICATION];
				const u8 *adatas[PERF_BATCH_VERIFICATION];
				u16 adatas_len[PERF_BATCH_VERIFICATION];
				/* We need 2 * n + 1 scratch pad storage, compute this with max */
				verify_batch_scratch_pad scratch_pad_area[(2 * PERF_BATCH_VERIFICATION) + 1];
				u32 scratch_pad_area_len = sizeof(scratch_pad_area);

				for(j = 0; j < PERF_BATCH_VERIFICATION; j++){
					signatures[j] = sig;
					signatures_len[j] = siglen;
					messages[j] = msg;
					messages_len[j] = msglen;
					pub_keys[j] = &(kp.pub_key);
					adatas[j] = c->adata;
					adatas_len[j] = c->adata_len;
				}
				ret = get_ms_time(&time1);
				if (ret) {
					ext_printf("Error when getting time\n");
					goto err;
				}
				ret = ec_verify_batch(signatures, signatures_len, pub_keys, messages, messages_len,
						PERF_BATCH_VERIFICATION, c->sig_type, c->hash_type, adatas, adatas_len, scratch_pad_area, &scratch_pad_area_len);
				if(ret){
					ext_printf("Error when verifying signature ec_verify_batch with batch %d\n", PERF_BATCH_VERIFICATION);
					goto err;
				}
				ret = get_ms_time(&time2);
				if (ret) {
					ext_printf("Error when getting time\n");
					goto err;
				}
				if (time2 < time1) {
					ext_printf("Error: time error (time2 < time1)\n");
					goto err;
				}
				cumulated_time_batch_verify += (time2 - time1);
				(*batch_verify_ok) = 1;
			}
			else{
				(*batch_verify_ok) = 0;
			}
		}

		if (n_perf_sign != NULL) {
			(*n_perf_sign) = (unsigned int)((PERF_NUM_OP * 1000ULL) / cumulated_time_sign);
		}
		if (n_perf_verif != NULL) {
			(*n_perf_verif) = (unsigned int)((PERF_NUM_OP * 1000ULL) / cumulated_time_verify);
		}
		if (n_perf_batch_verif != NULL) {
			if((*batch_verify_ok) == 1){
				(*n_perf_batch_verif) = (unsigned int)((PERF_NUM_OP * PERF_BATCH_VERIFICATION * 1000ULL) / cumulated_time_batch_verify);
			}
			else{
				(*n_perf_batch_verif) = 0;
			}
		}
	}
	ret = 0;
 err:
	return ret;
}


static int perf_test_one(const ec_sig_mapping *sig, const hash_mapping *hash,
			 const ec_mapping *ec)
{
	char test_name[MAX_CURVE_NAME_LEN + MAX_HASH_ALG_NAME_LEN +
		       MAX_SIG_ALG_NAME_LEN + 2];
	const unsigned int tn_size = sizeof(test_name) - 1; /* w/o trailing 0 */
	unsigned int n_perf_sign = 0, n_perf_verif = 0, n_perf_batch_verif = 0;
	unsigned char batch_verify_ok = 0;
	const char *crv_name;
	ec_test_case t;
	int ret;
	u32 len;

	MUST_HAVE((sig != NULL), ret, err);
	MUST_HAVE((hash != NULL), ret, err);
	MUST_HAVE((ec != NULL), ret, err);

	ret = local_memset(test_name, 0, sizeof(test_name)); EG(ret, err);

	crv_name = (const char *)PARAM_BUF_PTR((ec->params)->name);

	/* Generate the test name */
	ret = local_memset(test_name, 0, tn_size + 1); EG(ret, err);
	ret = local_strncpy(test_name, sig->name, tn_size); EG(ret, err);
	ret = local_strlen(test_name, &len); EG(ret, err);
	ret = local_strncat(test_name, "-", tn_size - len); EG(ret, err);
	ret = local_strlen(test_name, &len); EG(ret, err);
	ret = local_strncat(test_name, hash->name, tn_size - len); EG(ret, err);
	ret = local_strlen(test_name, &len); EG(ret, err);
	ret = local_strncat(test_name, "/", tn_size - len); EG(ret, err);
	ret = local_strlen(test_name, &len); EG(ret, err);
	ret = local_strncat(test_name, crv_name, tn_size - len); EG(ret, err);

	/* Create a test */
	t.name = test_name;
	t.ec_str_p = ec->params;
	t.priv_key = NULL;
	t.priv_key_len = 0;
	t.nn_random = NULL;
	t.hash_type = hash->type;
	t.msg = NULL;
	t.msglen = 0;
	t.sig_type = sig->type;
	t.exp_sig = NULL;
	t.exp_siglen = 0;
	{
		{
			t.adata = NULL;
			t.adata_len = 0;
		}
	}

	/* Sign and verify some random data during some time */
	ret = ec_performance_test(&t, &n_perf_sign, &n_perf_verif, &n_perf_batch_verif, &batch_verify_ok);
	OPENMP_LOCK();
	if(batch_verify_ok == 1){
		ext_printf("[%s] %30s perf: %u sign/s and %u verif/s, %u batch verif/s (for %u batch)\n",
			   ret ? "-" : "+", t.name, n_perf_sign, n_perf_verif, n_perf_batch_verif, (unsigned int)PERF_BATCH_VERIFICATION);
		if ((n_perf_sign == 0) || (n_perf_verif == 0) || (n_perf_batch_verif == 0)) {
			ext_printf("\t(0 is less than one sig/verif per sec)\n");
		}
	}
	else{
		ext_printf("[%s] %30s perf: %u sign/s and %u verif/s\n",
			   ret ? "-" : "+", t.name, n_perf_sign, n_perf_verif);
		if ((n_perf_sign == 0) || (n_perf_verif == 0)) {
			ext_printf("\t(0 is less than one sig/verif per sec)\n");
		}
	}
	OPENMP_UNLOCK();

err:
	return ret;
}

int perform_performance_test(const char *sig, const char *hash, const char *curve)
{
	unsigned int i, j, k;
	int ret, check;

	/* Perform performance tests like "openssl speed" command */
	ext_printf("======= Performance test ========================\n");
#ifdef OPENMP_SELF_TESTS
	ext_printf("== NOTE: OpenMP parallelization is not applied to performance tests ...\n");
	ext_printf("== (because of CPU/cores shared ressources such as caches, BPU, etc.)\n");
#endif
	for (i = 0; ec_sig_maps[i].type != UNKNOWN_ALG; i++) {
		for (j = 0; hash_maps[j].type != UNKNOWN_HASH_ALG; j++) {
			for (k = 0; k < EC_CURVES_NUM; k++) {
				if(sig != NULL){
					ret = are_str_equal(ec_sig_maps[i].name, sig, &check); OPENMP_EG(ret, err);
					if(!check){
						continue;
					}
				}
				if(hash != NULL){
					ret = are_str_equal(hash_maps[j].name, hash, &check); OPENMP_EG(ret, err);
					if(!check){
						continue;
					}
				}
				if(curve != NULL){
					ret = are_str_equal((const char*)ec_maps[k].params->name->buf, curve, &check); OPENMP_EG(ret, err);
					if(!check){
						continue;
					}
				}
				/* If we have EDDSA25519 or EDDSA448, we only accept specific hash functions.
				 * Skip the other tests.
				 */

				ret = perf_test_one(&ec_sig_maps[i],
						    &hash_maps[j],
						    &ec_maps[k]);
				if (ret) {
					goto err;
				}
			}
		}
	}

	return 0;

err:
	return -1;
}
