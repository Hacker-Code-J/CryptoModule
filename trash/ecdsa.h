#ifndef ECDSA_H
#define ECDSA_H

#include <flint/fmpz.h>

/****************************************************************************************
 * 1) PARAMETERS: a single prime‐field curve. 
 *    You can swap these out for any Fp curve (e.g. a NIST P-curve), as long as p,a,b,G,n 
 *    fit into fmpz.
 ****************************************************************************************/

/* Example: a tiny toy curve over a 160-bit prime (for illustration only). 
 * Real apps should pick a > 224- or 256-bit prime. */
#define EC_P_HEX    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73"  /* 160-bit prime */
#define EC_A_HEX    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70"  /* a = p - 3 */
#define EC_B_HEX    "00C9517D06D98E2638D55AA]])

#define EC_GX_HEX   "4A96B5688EF573284664698968C38BB913CBFC82"
#define EC_GY_HEX   "23A628553168947D59DCC912042351377AC5FB32"
#define EC_N_HEX    "0100000000000000000001F4C8F927AED3CA752257"

/* Forward declare a struct for curve parameters (Fp). */
typedef struct {
    fmpz_t p, a, b;       /* prime p; curve eqn: y^2 = x^3 + a x + b mod p */
    fmpz_t Gx, Gy;        /* base point G = (Gx,Gy) */
    fmpz_t n;             /* order of G */
} ec_curve_fp_t;

/****************************************************************************************
 * 2) POINT REPRESENTATION: affine (x,y) plus an "infinity" flag
 ****************************************************************************************/
typedef struct {
    fmpz_t x, y;
    int     is_infinity;  /* 1 = point at infinity; else 0 */
} ec_pt_fp_t;

/****************************************************************************************
 * 3) Fp HELPER FUNCTIONS (mod p)
 *      - init/destroy/zero/copy
 *      - add, sub, mul, inv, neg, cmp, set_str, to_str, random
 ****************************************************************************************/
void fp_init(fmpz_t r);
void fp_clear(fmpz_t r);
void fp_set_hex(fmpz_t r, const char *hex);
void fp_copy(fmpz_t r, const fmpz_t a);
void fp_add(fmpz_t r, const fmpz_t a, const fmpz_t b, const fmpz_t p);
void fp_sub(fmpz_t r, const fmpz_t a, const fmpz_t b, const fmpz_t p);
void fp_mul(fmpz_t r, const fmpz_t a, const fmpz_t b, const fmpz_t p);
void fp_inv(fmpz_t r, const fmpz_t a, const fmpz_t p);
void fp_neg(fmpz_t r, const fmpz_t a, const fmpz_t p);
int  fp_cmp(const fmpz_t a, const fmpz_t b);
void fp_set_ui(fmpz_t r, unsigned long v);
void fp_set(fmpz_t r, const fmpz_t a);
void fp_set_rand(fmpz_t r, const fmpz_t p);
char *fp_get_str(const fmpz_t a);  /* returns newly malloc'ed hex string */

/****************************************************************************************
 * 4) EC POINT FUNCTIONS
 *      - point init/clear/set_infty/set/copy
 *      - point addition, doubling, scalar multiply
 *      - check that P lies on curve
 ****************************************************************************************/
void ec_pt_init(ec_pt_fp_t *P);
void ec_pt_clear(ec_pt_fp_t *P);
void ec_pt_set_infty(ec_pt_fp_t *P);
void ec_pt_copy(ec_pt_fp_t *R, const ec_pt_fp_t *P);
void ec_pt_set(ec_pt_fp_t *P, const fmpz_t x, const fmpz_t y);

int  ec_is_on_curve(const ec_curve_fp_t *C, const ec_pt_fp_t *P);

/* R = P + Q mod curve C */
void ec_add(ec_pt_fp_t *R, const ec_pt_fp_t *P, const ec_pt_fp_t *Q, const ec_curve_fp_t *C);
/* R = 2P */
void ec_double(ec_pt_fp_t *R, const ec_pt_fp_t *P, const ec_curve_fp_t *C);
/* R = k * P using (simple) double-and-add; 0 <= k < n */
void ec_mul(ec_pt_fp_t *R, const ec_pt_fp_t *P, const fmpz_t k, const ec_curve_fp_t *C);

/****************************************************************************************
 * 5) ECDSA KEYGEN / SIGN / VERIFY
 ****************************************************************************************/
/* keypair = (priv, pub).  priv in [1..n-1]; pub = priv*G. */
typedef struct {
    fmpz_t    priv;   /* private scalar d */
    ec_pt_fp_t pub;   /* public point Q = d*G */
} ecdsa_keypair_t;

void ecdsa_keypair_init(ecdsa_keypair_t *KP);
void ecdsa_keypair_clear(ecdsa_keypair_t *KP);

/* Generates a random keypair.  Requires RNG seeded externally. */
int ecdsa_gen_key(ecdsa_keypair_t *KP, const ec_curve_fp_t *C);

/* Signature = (r,s), both in [1..n-1].  Returns 0 on success, -1 on error. */
int ecdsa_sign(fmpz_t r, fmpz_t s,
               const fmpz_t priv,
               const unsigned char *msg, size_t msglen,
               const ec_curve_fp_t *C);

/* Returns 1 if valid, 0 if invalid, -1 on error. */
int ecdsa_verify(const fmpz_t r, const fmpz_t s,
                 const ec_pt_fp_t *pub,
                 const unsigned char *msg, size_t msglen,
                 const ec_curve_fp_t *C);

/****************************************************************************************
 * 6) INITIALIZE / DESTROY CURVE
 ****************************************************************************************/
/* Fill C->p,a,b,Gx,Gy,n from hex strings defined above */
void ec_curve_init(ec_curve_fp_t *C);
void ec_curve_clear(ec_curve_fp_t *C);

#endif /* ECDSA_H */
