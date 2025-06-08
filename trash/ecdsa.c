#include "ecdsa.h"
#include <stdlib.h>
#include <string.h>

/*--------------------------------------------------------------------------------------
 *  Section 3: Fp HELPER IMPLEMENTATIONS (mod p)
 *------------------------------------------------------------------------------------*/

void fp_init(fmpz_t r) {
    fmpz_init(r);
}

void fp_clear(fmpz_t r) {
    fmpz_clear(r);
}

void fp_set_hex(fmpz_t r, const char *hex) {
    fmpz_set_str(r, hex, 16);
}

void fp_copy(fmpz_t r, const fmpz_t a) {
    fmpz_set(r, a);
}

void fp_add(fmpz_t r, const fmpz_t a, const fmpz_t b, const fmpz_t p) {
    fmpz_add(r, a, b);
    fmpz_mod(r, r, p);
}

void fp_sub(fmpz_t r, const fmpz_t a, const fmpz_t b, const fmpz_t p) {
    fmpz_sub(r, a, b);
    fmpz_mod(r, r, p);
}

void fp_mul(fmpz_t r, const fmpz_t a, const fmpz_t b, const fmpz_t p) {
    fmpz_mul(r, a, b);
    fmpz_mod(r, r, p);
}

void fp_inv(fmpz_t r, const fmpz_t a, const fmpz_t p) {
    /* r = a^{-1} mod p */
    if (fmpz_is_zero(a)) {
        /* error: inversion of zero */
        fmpz_set_ui(r, 0);
        return;
    }
    fmpz_invmod(r, a, p);
}

void fp_neg(fmpz_t r, const fmpz_t a, const fmpz_t p) {
    if (fmpz_is_zero(a)) {
        fmpz_set_ui(r, 0);
    } else {
        fmpz_sub(r, p, a);
        fmpz_mod(r, r, p);
    }
}

int fp_cmp(const fmpz_t a, const fmpz_t b) {
    return fmpz_cmp(a, b);
}

void fp_set_ui(fmpz_t r, unsigned long v) {
    fmpz_set_ui(r, v);
}

void fp_set(fmpz_t r, const fmpz_t a) {
    fmpz_set(r, a);
}

void fp_set_rand(fmpz_t r, const fmpz_t p) {
    fmpz_randm(r, p);  /* uniform in [0..p-1) */
}

char *fp_get_str(const fmpz_t a) {
    return fmpz_get_str(NULL, 16, a);
}

/*--------------------------------------------------------------------------------------
 *  Section 6: EC CURVE INIT/CLEAR
 *------------------------------------------------------------------------------------*/

static ec_curve_fp_t CURVE;

/* Initialize CURVE from the hard-coded hex params above */
void ec_curve_init(ec_curve_fp_t *C) {
    fp_init(C->p);
    fp_init(C->a);
    fp_init(C->b);
    fp_init(C->Gx);
    fp_init(C->Gy);
    fp_init(C->n);

    fp_set_hex(C->p, EC_P_HEX);
    fp_set_hex(C->a, EC_A_HEX);
    fp_set_hex(C->b, EC_B_HEX);
    fp_set_hex(C->Gx, EC_GX_HEX);
    fp_set_hex(C->Gy, EC_GY_HEX);
    fp_set_hex(C->n, EC_N_HEX);
}

void ec_curve_clear(ec_curve_fp_t *C) {
    fp_clear(C->p);
    fp_clear(C->a);
    fp_clear(C->b);
    fp_clear(C->Gx);
    fp_clear(C->Gy);
    fp_clear(C->n);
}

/*--------------------------------------------------------------------------------------
 *  Section 4: EC PT HELPERS (affine coords)
 *------------------------------------------------------------------------------------*/

void ec_pt_init(ec_pt_fp_t *P) {
    fp_init(P->x);
    fp_init(P->y);
    P->is_infinity = 1;
}

void ec_pt_clear(ec_pt_fp_t *P) {
    fp_clear(P->x);
    fp_clear(P->y);
}

void ec_pt_set_infty(ec_pt_fp_t *P) {
    P->is_infinity = 1;
}

void ec_pt_copy(ec_pt_fp_t *R, const ec_pt_fp_t *P) {
    if (P->is_infinity) {
        R->is_infinity = 1;
    } else {
        R->is_infinity = 0;
        fp_copy(R->x, P->x);
        fp_copy(R->y, P->y);
    }
}

void ec_pt_set(ec_pt_fp_t *P, const fmpz_t x, const fmpz_t y) {
    P->is_infinity = 0;
    fp_copy(P->x, x);
    fp_copy(P->y, y);
}

int ec_is_on_curve(const ec_curve_fp_t *C, const ec_pt_fp_t *P) {
    if (P->is_infinity) return 1;

    fmpz_t lhs, rhs, tmp;
    fp_init(lhs);
    fp_init(rhs);
    fp_init(tmp);

    /* lhs = y^2 mod p */
    fp_mul(lhs, P->y, P->y, C->p);

    /* tmp = x^3 + a x + b mod p */
    fp_mul(tmp, P->x, P->x, C->p);          /* tmp = x^2 */
    fp_mul(tmp, tmp, P->x, C->p);           /* tmp = x^3 */
    fmpz_t ax; fp_init(ax);
    fp_mul(ax, C->a, P->x, C->p);           /* ax = a * x */
    fp_add(rhs, tmp, ax, C->p);             /* rhs = x^3 + a x */
    fp_add(rhs, rhs, C->b, C->p);            /* rhs = x^3 + a x + b */

    int eq = (fp_cmp(lhs, rhs) == 0);

    fp_clear(lhs);
    fp_clear(rhs);
    fp_clear(tmp);
    fp_clear(ax);
    return eq;
}

/* R = P + Q. Uses slope = (y2-y1)/(x2-x1) mod p; then x3 = slope^2 - x1 - x2; y3 = slope(x1-x3) - y1 */
void ec_add(ec_pt_fp_t *R, const ec_pt_fp_t *P, const ec_pt_fp_t *Q, const ec_curve_fp_t *C) {
    if (P->is_infinity) { ec_pt_copy(R, Q); return; }
    if (Q->is_infinity) { ec_pt_copy(R, P); return; }

    if (fp_cmp(P->x, Q->x) == 0) {
        /* either P == Q or P == -Q */
        fmpz_t negy; fp_init(negy);
        fp_neg(negy, Q->y, C->p);
        if (fp_cmp(P->y, negy) == 0) {
            ec_pt_set_infty(R);
            fp_clear(negy);
            return;
        }
        fp_clear(negy);
        /* otherwise point doubling */
        ec_double(R, P, C);
        return;
    }

    /* slope = (y2 - y1)/(x2 - x1) mod p */
    fmpz_t slope, dx, dy, inv_dx;
    fp_init(slope);
    fp_init(dx);
    fp_init(dy);
    fp_init(inv_dx);

    fp_sub(dy, Q->y, P->y, C->p);      /* dy = y2 - y1 */
    fp_sub(dx, Q->x, P->x, C->p);      /* dx = x2 - x1 */
    fp_inv(inv_dx, dx, C->p);          /* inv_dx = dx^{-1} */
    fp_mul(slope, dy, inv_dx, C->p);   /* slope = dy * inv_dx */

    /* x3 = slope^2 - x1 - x2 mod p */
    fmpz_t slope2, x3, y3, tmp;
    fp_init(slope2);
    fp_init(x3);
    fp_init(y3);
    fp_init(tmp);

    fp_mul(slope2, slope, slope, C->p);    /* slope2 = slope^2 */
    fp_sub(x3, slope2, P->x, C->p);        /* x3 = slope^2 - x1 */
    fp_sub(x3, x3, Q->x, C->p);            /* x3 = slope^2 - x1 - x2 */

    /* y3 = slope*(x1 - x3) - y1 mod p */
    fp_sub(tmp, P->x, x3, C->p);            /* tmp = x1 - x3 */
    fp_mul(y3, slope, tmp, C->p);          /* y3 = slope * (x1 - x3) */
    fp_sub(y3, y3, P->y, C->p);            /* y3 = slope*(x1-x3) - y1 */

    R->is_infinity = 0;
    fp_copy(R->x, x3);
    fp_copy(R->y, y3);

    fp_clear(slope);
    fp_clear(dx);
    fp_clear(dy);
    fp_clear(inv_dx);
    fp_clear(slope2);
    fp_clear(x3);
    fp_clear(y3);
    fp_clear(tmp);
}

/* R = 2P. Uses slope = (3x1^2 + a)/(2y1) mod p; then x3 = slope^2 - 2x1; y3 = slope(x1-x3) - y1 */
void ec_double(ec_pt_fp_t *R, const ec_pt_fp_t *P, const ec_curve_fp_t *C) {
    if (P->is_infinity) {
        ec_pt_set_infty(R);
        return;
    }
    if (fmpz_is_zero(P->y)) {
        /* tangent is vertical => point at infinity */
        ec_pt_set_infty(R);
        return;
    }

    fmpz_t slope, num, den, inv_den;
    fp_init(slope);
    fp_init(num);
    fp_init(den);
    fp_init(inv_den);

    /* num = 3*x1^2 + a mod p */
    fmpz_t x1sq; fp_init(x1sq);
    fp_mul(x1sq, P->x, P->x, C->p);          /* x1sq = x1^2 */
    fmpz_mul_ui(num, x1sq, 3);               /* num = 3*x1^2 */
    fmpz_mod(num, num, C->p);                /* mod p */
    fp_add(num, num, C->a, C->p);            /* num = 3*x1^2 + a */

    /* den = 2*y1 mod p */
    fmpz_mul_ui(den, P->y, 2);
    fmpz_mod(den, den, C->p);

    fp_inv(inv_den, den, C->p);              /* inv_den = (2*y1)^{-1} */
    fp_mul(slope, num, inv_den, C->p);       /* slope = num*inv_den */

    /* x3 = slope^2 - 2*x1 mod p */
    fmpz_t slope2, x3, y3, tmp; 
    fp_init(slope2);
    fp_init(x3);
    fp_init(y3);
    fp_init(tmp);

    fp_mul(slope2, slope, slope, C->p);      /* slope2 = slope^2 */
    fp_sub(x3, slope2, P->x, C->p);          /* x3 = slope^2 - x1 */
    fp_sub(x3, x3, P->x, C->p);             /* x3 = slope^2 - 2*x1 */

    /* y3 = slope*(x1 - x3) - y1 mod p */
    fp_sub(tmp, P->x, x3, C->p);             /* tmp = x1 - x3 */
    fp_mul(y3, slope, tmp, C->p);            /* y3 = slope*(x1 - x3) */
    fp_sub(y3, y3, P->y, C->p);             /* y3 = slope*(x1-x3) - y1 */

    R->is_infinity = 0;
    fp_copy(R->x, x3);
    fp_copy(R->y, y3);

    fp_clear(slope);
    fp_clear(num);
    fp_clear(den);
    fp_clear(inv_den);
    fp_clear(x1sq);
    fp_clear(slope2);
    fp_clear(x3);
    fp_clear(y3);
    fp_clear(tmp);
}

/* R = k*P via simple double-and-add. k is fmpz (0 <= k < n). */
void ec_mul(ec_pt_fp_t *R, const ec_pt_fp_t *P, const fmpz_t k, const ec_curve_fp_t *C) {
    ec_pt_fp_t Q; ec_pt_init(&Q);
    ec_pt_set_infty(&Q);

    ec_pt_fp_t A; ec_pt_init(&A);
    ec_pt_copy(&A, P);

    fmpz_t kk; fp_init(kk);
    fp_copy(kk, k);

    /* while kk > 0 */
    while (!fmpz_is_zero(kk)) {
        if (fmpz_tstbit(kk, 0)) {
            /* add A to Q */
            ec_add(&Q, &Q, &A, C);
        }
        ec_double(&A, &A, C);
        fmpz_fdiv_q_2exp(kk, kk, 1);  /* kk >>= 1 */
    }
    ec_pt_copy(R, &Q);

    ec_pt_clear(&Q);
    ec_pt_clear(&A);
    fp_clear(kk);
}

/****************************************************************************************
 *  Section 5: ECDSA KEYGEN / SIGN / VERIFY
 *------------------------------------------------------------------------------------*/

/* STRUCT INIT/CLEAR */
void ecdsa_keypair_init(ecdsa_keypair_t *KP) {
    fp_init(KP->priv);
    ec_pt_init(&KP->pub);
}

void ecdsa_keypair_clear(ecdsa_keypair_t *KP) {
    fp_clear(KP->priv);
    ec_pt_clear(&KP->pub);
}

/* KEY GENERATION:
 *  priv <- random in [1..n-1]
 *  pub  = priv * G
 *  Returns 0 on success, -1 if priv==0 or priv>=n
 */
int ecdsa_gen_key(ecdsa_keypair_t *KP, const ec_curve_fp_t *C) {
    fmpz_t one; fp_init(one); fp_set_ui(one, 1);

    do {
        fp_set_rand(KP->priv, C->n);       /* uniform in [0..n-1] */
    } while (fmpz_is_zero(KP->priv) || (fmpz_cmp(KP->priv, C->n) >= 0));

    /* pub = priv * G */
    ec_pt_fp_t G; ec_pt_init(&G);
    ec_pt_set(&G, C->Gx, C->Gy);

    ec_mul(&KP->pub, &G, KP->priv, C);

    ec_pt_clear(&G);
    fp_clear(one);
    return 0;
}

/*--------------------------------------------------------------------------------------
 *  SHA-256 STUB
 *  You must replace these with a real SHA-256 (or SHA-1) implementation.
 *  The interface:
 *     void sha256(const unsigned char *m, size_t mlen, unsigned char out32[32]);
 *------------------------------------------------------------------------------------*/
void sha256(const unsigned char *m, size_t mlen, unsigned char out32[32]) {
    /* INSECURE PLACEHOLDER.  Replace with real SHA-256. */
    /* For testing, just zero out the hash: */
    memset(out32, 0, 32);
}

/*--------------------------------------------------------------------------------------
 *  ecdsa_sign( r, s = sign(priv, msg) )
 *------------------------------------------------------------------------------------*/
int ecdsa_sign(fmpz_t r, fmpz_t s,
               const fmpz_t priv,
               const unsigned char *msg, size_t msglen,
               const ec_curve_fp_t *C)
{
    /* 1) hash = SHA256(msg) -> e = integer mod n */
    unsigned char hash[32];
    sha256(msg, msglen, hash);

    /* e = hash mod n */
    fmpz_t e; fp_init(e);
    fmpz_set_str(e, "0", 10);
    for(int i = 0; i < 32; i++) {
        fmpz_mul_ui(e, e, 256);
        fmpz_add_ui(e, e, hash[i]);
    }
    fmpz_mod(e, e, C->n);

    fmpz_t k, k_inv; fp_init(k); fp_init(k_inv);
    ec_pt_fp_t Rpt; ec_pt_init(&Rpt);

    do {
        /* 2) pick random k in [1..n-1] */
        do {
            fp_set_rand(k, C->n);
        } while (fmpz_is_zero(k) || (fmpz_cmp(k, C->n) >= 0));

        /* 3) Rpt = k * G;  compute r = x_R mod n */
        ec_pt_fp_t G; ec_pt_init(&G);
        ec_pt_set(&G, C->Gx, C->Gy);
        ec_mul(&Rpt, &G, k, C);
        ec_pt_clear(&G);

        /* r = Rpt.x mod n */
        fmpz_mod(r, Rpt.x, C->n);
        if (fmpz_is_zero(r)) continue;

        /* 4) k_inv = k^{-1} mod n */
        fp_inv(k_inv, k, C->n); 

        /* 5) s = k_inv * (e + priv * r) mod n */
        fmpz_t tmp; fp_init(tmp);
        fmpz_mul(tmp, priv, r);     /* tmp = priv * r */
        fmpz_add(tmp, tmp, e);      /* tmp = e + priv * r */
        fmpz_mod(tmp, tmp, C->n);
        fp_mul(s, k_inv, tmp, C->n); /* s = k_inv*tmp mod n */

        fp_clear(tmp);
        if (fmpz_is_zero(s)) continue;

        break;
    } while (1);

    ec_pt_clear(&Rpt);
    fp_clear(e);
    fp_clear(k);
    fp_clear(k_inv);
    return 0;
}

/*--------------------------------------------------------------------------------------
 *  ecdsa_verify( 1/0, -1=error ) 
 *------------------------------------------------------------------------------------*/
int ecdsa_verify(const fmpz_t r, const fmpz_t s,
                 const ec_pt_fp_t *pub,
                 const unsigned char *msg, size_t msglen,
                 const ec_curve_fp_t *C)
{
    /* 0 < r,s < n ? */
    if (fmpz_cmp_ui(r, 1) < 0 || fmpz_cmp(r, C->n) >= 0) return 0;
    if (fmpz_cmp_ui(s, 1) < 0 || fmpz_cmp(s, C->n) >= 0) return 0;

    /* 1) hash = SHA256(msg) -> e = integer mod n */
    unsigned char hash[32];
    sha256(msg, msglen, hash);

    fmpz_t e; fp_init(e);
    fmpz_set_str(e, "0", 10);
    for(int i = 0; i < 32; i++) {
        fmpz_mul_ui(e, e, 256);
        fmpz_add_ui(e, e, hash[i]);
    }
    fmpz_mod(e, e, C->n);

    /* 2) w = s^{-1} mod n */
    fmpz_t w; fp_init(w);
    fp_inv(w, s, C->n);

    /* 3) u1 = e*w mod n; u2 = r*w mod n */
    fmpz_t u1, u2; fp_init(u1); fp_init(u2);
    fp_mul(u1, e, w, C->n);
    fp_mul(u2, r, w, C->n);

    /* 4) Rpt = u1*G + u2*Q */
    ec_pt_fp_t u1G, u2Q, Rpt; 
    ec_pt_init(&u1G); ec_pt_init(&u2Q); ec_pt_init(&Rpt);

    ec_pt_fp_t G; ec_pt_init(&G);
    ec_pt_set(&G, C->Gx, C->Gy);

    ec_mul(&u1G, &G, u1, C);
    ec_mul(&u2Q, pub, u2, C);
    ec_add(&Rpt, &u1G, &u2Q, C);

    ec_pt_clear(&u1G);
    ec_pt_clear(&u2Q);
    ec_pt_clear(&G);

    if (Rpt.is_infinity) {
        ec_pt_clear(&Rpt);
        fp_clear(e); fp_clear(w); fp_clear(u1); fp_clear(u2);
        return 0;  /* invalid */
    }

    /* 5) v = x_R mod n */
    fmpz_t v; fp_init(v);
    fmpz_mod(v, Rpt.x, C->n);

    int valid = (fp_cmp(v, r) == 0);

    ec_pt_clear(&Rpt);
    fp_clear(e); fp_clear(w); fp_clear(u1); fp_clear(u2); fp_clear(v);

    return valid;
}
