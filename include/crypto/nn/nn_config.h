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
#ifndef __NN_CONFIG_H__
#define __NN_CONFIG_H__
#include <crypto/words/words.h>
#include <crypto/utils/utils.h>
/*
 * We include the curves list to adapt the maximum NN size to P and Q
 * (prime and order of the curve).
 */
#include <crypto/curves/curves_list.h>
/*
 * We also include the hash layer to adapt the maximum NN size to the
 * maximum digest size as we have to import full digests as NN when dealing
 * with some signature algorithms.
 *
 */
// #include <crypto/hash/hash_algs.h>

/*
 * All the big num used in the lib are statically allocated. This constant
 * must be defined (here or during build) to provide an upper limit on the
 * size in bits of the numbers the instance of the lib you will build will
 * handle. Note that this value does not prevent the declaration and use
 * of smaller numbers.
 *
 * Rationale for the default value: the main purpose of the lirary is to
 * support for an ECC implementation. ATM, a forseeable upper limit for the
 * numbers that will be dealt with is 521 bits.
 *
 * However, the user is allowed to overload the maximum bit length of the
 * numbers through the USER_NN_BIT_LEN macro definition (see below). A
 * hard limit 'nn_max' for this size depends on the word size and verifies
 * the following equation (with w being the word size):
 *
 *             floor((nn_max + w - 1) / w) * 3 = 255
 *
 * This equation is explained by elements given below, and by the fact that
 * the length in words of our big numbers are encoded on an u8. This yields
 * in max sizes of around 5300 bits for 64-bit words, around 2650 bits for
 * 32-bit words, and around 1300 bits for 16-bit words.
 *
 * Among all the functions we have, some need to handle something which
 * can be seen as a double, so we need twice the amount of bit above.
 * This is typically the case when two numbers are multiplied.
 * But then you usually want to divide this product by another number
 * of the initial size which generically requires shifting by the
 * original sized, whence the factor 3 below.
 *
 * Additionally, all numbers we handled are expected to have a length which
 * is a multiple of the word size we support, i.e. 64/32/16 bits. Hence the
 * rounding.
 */

/* Macro to round a bit length size to a word size */
#define BIT_LEN_ROUNDING(x, w) ((((x) + (w) - 1) / (w)) * (w))

/*
 * Macro to round a bit length size of a NN value to a word size, and
 * to a size compatible with the arithmetic operations of the library
 * (usually 3 times the size of the input numbers, see explanations above).
 */
#define MAX_BIT_LEN_ROUNDING(x, w) (((((x) + (w) - 1) / (w)) * (w)) * 3)

#define NN_MAX_BIT_LEN MAX_BIT_LEN_ROUNDING(CURVES_MAX_P_BIT_LEN, WORD_BITS)
#define NN_MAX_BASE CURVES_MAX_P_BIT_LEN

/************/
/* NN maximum internal lengths to be "safe" in our computations */
#define NN_MAX_BYTE_LEN (NN_MAX_BIT_LEN / 8)
#define NN_MAX_WORD_LEN (NN_MAX_BYTE_LEN / WORD_BYTES)
/* Usable maximum sizes, to be used by the end user to be "safe" in
 * all the computations.
 */
#define NN_USABLE_MAX_BIT_LEN  (NN_MAX_BASE)
#define NN_USABLE_MAX_BYTE_LEN ((BIT_LEN_ROUNDING(NN_USABLE_MAX_BIT_LEN, 8)) / 8)
#define NN_USABLE_MAX_WORD_LEN ((BIT_LEN_ROUNDING(NN_USABLE_MAX_BIT_LEN, WORD_BITS)) / WORD_BITS)

/* Sanity checks */
#if (NN_USABLE_MAX_BIT_LEN > NN_MAX_BIT_LEN) || (NN_USABLE_MAX_BYTE_LEN > NN_MAX_BYTE_LEN) || (NN_USABLE_MAX_WORD_LEN > NN_MAX_WORD_LEN)
#error "usable maximum length > internal maximum length, this should not happen!"
#endif

#if (NN_MAX_WORD_LEN > 255)
#error "nn.wlen is encoded on an u8. NN_MAX_WORD_LEN cannot be larger than 255!"
#endif

#endif /* __NN_CONFIG_H__ */