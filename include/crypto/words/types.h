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
#ifndef __TYPES_H__
#define __TYPES_H__

/*** Handling the target compiler and its specificities ***/

#define ATTRIBUTE_UNUSED __attribute__((unused))
#define ATTRIBUTE_USED __attribute__((used))
#define ATTRIBUTE_PACKED __attribute__((packed))
#define ATTRIBUTE_SECTION(a) __attribute__((__section__((a))))

#define ATTRIBUTE_WARN_UNUSED_RET
#define IGNORE_RET_VAL(a) (a)


/* Macro to trick the compiler of thinking a variable is used.
 * Although this should not happen, sometimes because of #define
 * oddities we might force this.
 */
#define FORCE_USED_VAR(a) ((void)(a))

#ifndef __cplusplus
#define REGISTER register
#else
/* NOTE: the 'register' keyword is not allowed in C++, so
 * we avoid its usage there. */
#define REGISTER
#endif

/*** Handling the types ****/
/*
 * User explicitly needs to build w/ stdlib. Let's include the headers
 * we need to get basic types: (uint*_t), NULL, etc. You can see below
 * (i.e. under #else) what is precisely needed.
 */
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>

#endif /* __TYPES_H__ */
