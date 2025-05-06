/* FILE: src/mode/mode_gcm.c */

/**
 * @file mode_gcm.c
 * @brief This file implements the GCM (Galois/Counter Mode) mode of operation for block ciphers.
 * @details The GCM mode is an authenticated encryption mode that 
 *          provides both confidentiality and integrity.
 */

#include "../../include/block_cipher/api_block_cipher.h"
#include "../../include/mode/api_mode.h"
#include "../../include/mode/mode_gcm.h"
#include "../../include/cryptomodule_utils.h"
#include "../../include/api_cryptomodule.h"

static void gf128_Hmul(u8 state[16], const u8 HT[256 * 16], const u8 R0[256], const u8 R1[256]);
static void ghash(u8* msg, size_t msg_len, u8 HT[256 * 16], u8 R0[256], u8 R1[256], u8 tag[16]);

static const ModeOfOperationApi GCM_MODE_API = {
    .mode_name    = "GCM",
    .mode_init    = NULL,
    .mode_process_with_tag = NULL,  // use gcm_encrypt_with_tag directly
    .mode_dispose = NULL
};

const ModeOfOperationApi* get_gcm_api(void) { return &GCM_MODE_API; }

/*
 * gf128_Hmul: Multiply two 128-bit values in GF(2^128) with table.
*/
void gf128_Hmul(u8 state[16], const u8 HT[256 * 16], const u8 R0[256], const u8 R1[256]) {
    u8 res[16] = { 0x00,}; // Result of the multiplication
    u8 poly;   // Polynomial in GF(2^8)

    for (int i = 0; i < 16; i++) {
        poly = state[15 - i];
        const u8* row = HT + (poly << 4);
        for (int j = 0; j < 16; j++)
            res[j] ^= row[j];
        poly = res[15];
        for (int j = 15; j > 0; j--)
            res[j] = res[j - 1];
        res[0] = R0[poly];
        res[1] ^= R1[poly];
    }

    poly = state[0];
    const u8* row0 = HT + (poly << 4);
    for (int i = 0; i < 16; i++)
        state[i] = res[i] ^ row0[i];
}

/*
 * ghash: tag <- (…((0 ^ M[0])·H ^ M[1])·H ... ^ M[n-1])·H
 * Uses a 256×16 lookup table for GF(2^128) multiplication.
 */
void ghash(u8* msg, size_t msg_len, u8 HT[256 * 16], u8 R0[256], u8 R1[256], u8 tag[16]) {
    size_t i, j;
    u8 out_tag[16] = { 0x00, }; // Output tag

    for (i = 0; i < msg_len; i++) {
        const u8 *blk = msg + (i << 4);

        for (j = 0; j < 16; j++)
            out_tag[j] ^= blk[j];

        gf128_Hmul(out_tag, HT, R0, R1);
    }

    memcpy(tag, out_tag, 16);
}


// /**
//  * @brief Increment only the low 32 bits of a 128-bit counter (bytes 12-15).
//  * @details This function increments the counter used in GCM mode.
//  *          It is a 128-bit counter, but only the last 32 bits are incremented.
//  */
// static void gcm_inc_counter(u8* counter) {
//     for (int i = 15; i >= 0; i--) {
//         if (++counter[i] != 0) {
//             break;
//         }
//     }
// }


// void gf128_H_mul(u8* state, u8* HT, const u8* R0, const u8* R1) {
//     u8 tmp[16] = { 0x00, };
//     u8 poly;   // Polynomial in GF(2^8)

//     for (int i =0; i < 16; i++ ) {
//         poly = state[15 - i];
//         for (int j = 0; j < 16; j++) {
//             tmp[j] ^= (poly & 0x01) ? R0[j] : 0;
//             poly >>= 1;
//         }
//     }
// }