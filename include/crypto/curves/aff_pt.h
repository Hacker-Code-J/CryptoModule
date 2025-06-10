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
#ifndef __AFF_PT_H__
#define __AFF_PT_H__

#include <crypto/fp/fp.h>
#include <crypto/fp/fp_sqrt.h>
#include <crypto/curves/ec_shortw.h>

typedef struct {
	fp x;
	fp y;
	ec_shortw_crv_src_t crv;
	word_t magic;
} aff_pt;

typedef aff_pt *aff_pt_t;
typedef const aff_pt_t aff_pt_src_t;

int aff_pt_check_initialized(aff_pt_src_t in);
int aff_pt_init(aff_pt_t in, ec_shortw_crv_src_t curve);
int aff_pt_init_from_coords(aff_pt_t in,
			    ec_shortw_crv_src_t curve,
			    fp_src_t xcoord, fp_src_t ycoord);
void aff_pt_uninit(aff_pt_t in);
int aff_pt_y_from_x(fp_t y1, fp_t y2, fp_src_t x, ec_shortw_crv_src_t curve);
int is_on_shortw_curve(fp_src_t x, fp_src_t y, ec_shortw_crv_src_t curve, int *on_curve);
int aff_pt_is_on_curve(aff_pt_src_t pt, int *on_curve);
int ec_shortw_aff_copy(aff_pt_t out, aff_pt_src_t in);
int ec_shortw_aff_cmp(aff_pt_src_t in1, aff_pt_src_t in2, int *cmp);
int ec_shortw_aff_eq_or_opp(aff_pt_src_t in1, aff_pt_src_t in2,
			    int *eq_or_opp);
int aff_pt_import_from_buf(aff_pt_t pt,
			   const u8 *pt_buf,
			   u16 pt_buf_len, ec_shortw_crv_src_t crv);
int aff_pt_export_to_buf(aff_pt_src_t pt, u8 *pt_buf, u32 pt_buf_len);

 #endif /* __AFF_PT_H__ */
