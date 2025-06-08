/*
 * A small test program that:
 *  1) initializes curve params,
 *  2) generates a keypair,
 *  3) signs a sample message,
 *  4) verifies it,
 *  5) prints r,s and success/failure.
 */

#include <stdio.h>
#include <string.h>
#include "ecdsa.h"

int main(void)
{
    /* 1) init curve */
    ec_curve_fp_t C;
    ec_curve_init(&C);

    /* 2) generate keypair */
    ecdsa_keypair_t KP;
    ecdsa_keypair_init(&KP);

    if (ecdsa_gen_key(&KP, &C) != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }

    /* 3) print public key */
    char *Qx_hex = fp_get_str(KP.pub.x);
    char *Qy_hex = fp_get_str(KP.pub.y);
    printf("Public key Q:\n  x = %s\n  y = %s\n", Qx_hex, Qy_hex);
    free(Qx_hex);
    free(Qy_hex);

    /* 4) sign a message */
    const char *msg = "Hello, ECDSA toy example!";
    fmpz_t r, s;
    fp_init(r);
    fp_init(s);

    if (ecdsa_sign(r, s, KP.priv,
                   (const unsigned char*)msg, strlen(msg),
                   &C) != 0)
    {
        fprintf(stderr, "signing error\n");
        return 1;
    }

    char *r_hex = fp_get_str(r);
    char *s_hex = fp_get_str(s);
    printf("Signature:\n  r = %s\n  s = %s\n", r_hex, s_hex);
    free(r_hex);
    free(s_hex);

    /* 5) verify signature */
    int ok = ecdsa_verify(r, s, &KP.pub,
                          (const unsigned char*)msg, strlen(msg),
                          &C);
    printf("Signature verify: %s\n", ok ? "SUCCESS" : "FAIL");

    /* 6) cleanup */
    fp_clear(r);
    fp_clear(s);
    ecdsa_keypair_clear(&KP);
    ec_curve_clear(&C);

    return 0;
}
