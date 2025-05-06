/* FILE: src/block_cipher/block_cipher_aria.c */
/**
 * @file block_cipher_aria.c
 * @brief This file implements the ARIA block cipher encryption and decryption operations.
 * @details The implementation in this source code file references the following site:
 *          https://github.com/openssl/openssl/blob/master/crypto/aria/aria.c
 */

 #include "../../include/block_cipher/block_cipher_aria.h"

 /* Forward declarations of static functions. */
 static block_cipher_status_t aria_init(BlockCipherContext *ctx, const u8 *key, size_t key_len, size_t block_len, BlockCipherDirection dir);
 static block_cipher_status_t aria_process(BlockCipherContext *ctx, const u8 *in, u8 *out, BlockCipherDirection dir);
 static void aria_dispose(BlockCipherContext *ctx);

 /**
  * @brief The ARIA block cipher API.
  * @details This structure contains function pointers to the ARIA initialization, unified encryption/decryption function,
  *          and disposal functions.
  */
 static const BlockCipherApi ARIA_API = {
     .cipher_name    = "ARIA",
     .cipher_init    = aria_init,
     .cipher_process = aria_process,
     .cipher_dispose = aria_dispose
 };
 /**
  * @brief Get the ARIA block cipher API.
  * @return Pointer to the ARIA block cipher API structure.
  */
 const BlockCipherApi* get_aria_api(void) { return &ARIA_API; }

 block_cipher_status_t aria_init(BlockCipherContext *ctx, const u8 *key, size_t key_len, size_t block_len, BlockCipherDirection dir) {
     if (!ctx || !key || key_len == 0 || block_len != ARIA_BLOCK_SIZE) {
         return BLOCK_CIPHER_INVALID_PARAMETER;
     }

     ctx->cipher_api = get_aria_api();
     ctx->cipher_state.aria_internal.block_size = block_len;
     ctx->cipher_state.aria_internal.key_len = key_len;

     if (dir == BLOCK_CIPHER_ENCRYPTION) {
         aria_set_encrypt_key(key, key_len, ctx->cipher_state.aria_internal.round_keys);
     } else {
         aria_set_decrypt_key(key, key_len, ctx->cipher_state.aria_internal.round_keys);
     }

     return BLOCK_CIPHER_OK;
 }
 block_cipher_status_t aria_process(BlockCipherContext *ctx, const u8 *in, u8 *out, BlockCipherDirection dir) {
     if (!ctx || !in || !out) {
         return BLOCK_CIPHER_INVALID_PARAMETER;
     }

     if (dir == BLOCK_CIPHER_ENCRYPTION) {
         aria_encrypt(in, out, ctx->cipher_state.aria_internal.round_keys, ctx->cipher_state.aria_internal.nr);
     } else {
         aria_decrypt(in, out, ctx->cipher_state.aria_internal.round_keys, ctx->cipher_state.aria_internal.nr);
     }

     return BLOCK_CIPHER_OK;
 }
 void aria_dispose(BlockCipherContext *ctx) {
     if (!ctx) return;

     // Clear sensitive data
     memset(ctx->cipher_state.aria_internal.round_keys, 0, sizeof(ctx->cipher_state.aria_internal.round_keys));
     ctx->cipher_api = NULL;
 }

void aria_set_encrypt_key(const u8 *key, size_t bytes, u32 *rk) {
    return;
}
void aria_set_decrypt_key(const u8 *key, size_t bytes, u32 *rk) {
    return;
}
void aria_encrypt(const u8 *in, u8 *out, const u32 *rk, int r) {
    return;
}
void aria_decrypt(const u8 *in, u8 *out, const u32 *rk, int r) {
    return;
}

/*
 * Exclusive or two 128 bit values into the result.
 * It is safe for the result to be the same as the either input.
 */
static void xor128(u8 o[ARIA_BLOCK_SIZE], const u8 x[ARIA_BLOCK_SIZE], const u8 y[ARIA_BLOCK_SIZE]) {
    int i;
    for (i = 0; i < ARIA_BLOCK_SIZE; i++)
        o[i] = x[i] ^ y[i];
}

/*
 * Generalised circular rotate right and exclusive or function.
 * It is safe for the output to overlap either input.
 */
static void rotnr(unsigned int n, u8 o[ARIA_BLOCK_SIZE],
                              const u8 xor[ARIA_BLOCK_SIZE], const u8 z[ARIA_BLOCK_SIZE])
{
    const unsigned int bytes = n / 8, bits = n % 8;
    unsigned int i;
    u8 t[ARIA_BLOCK_SIZE];

    for (i = 0; i < ARIA_BLOCK_SIZE; i++)
        t[(i + bytes) % ARIA_BLOCK_SIZE] = z[i];
    for (i = 0; i < ARIA_BLOCK_SIZE; i++)
        o[i] = ((t[i] >> bits) |
                (t[i ? i - 1 : ARIA_BLOCK_SIZE - 1] << (8 - bits))) ^
                xor[i];
}

/*
 * Circular rotate 19 bits right and xor.
 * It is safe for the output to overlap either input.
 */
static void rot19r(u8 o[ARIA_BLOCK_SIZE], const u8 xor[ARIA_BLOCK_SIZE], const u8* z[ARIA_BLOCK_SIZE])
{
    rotnr(19, o, xor, z);
}

/*
 * Circular rotate 31 bits right and xor.
 * It is safe for the output to overlap either input.
 */
static void rot31r(u8 o[ARIA_BLOCK_SIZE], const u8 xor[ARIA_BLOCK_SIZE], const u8* z[ARIA_BLOCK_SIZE])
{
    rotnr(31, o, xor, z);
}

/*
 * Circular rotate 61 bits left and xor.
 * It is safe for the output to overlap either input.
 */
static void rot61l(u8 o[ARIA_BLOCK_SIZE], const u8 xor[ARIA_BLOCK_SIZE], const u8* z[ARIA_BLOCK_SIZE])
{
    rotnr(8 * ARIA_BLOCK_SIZE - 61, o, xor, z);
}

/*
 * Circular rotate 31 bits left and xor.
 * It is safe for the output to overlap either input.
 */
static void rot31l(u8 o[ARIA_BLOCK_SIZE], const u8 xor[ARIA_BLOCK_SIZE], const u8* z[ARIA_BLOCK_SIZE])
{
    rotnr(8 * ARIA_BLOCK_SIZE - 31, o, xor, z);
}

/*
 * Circular rotate 19 bits left and xor.
 * It is safe for the output to overlap either input.
 */
static void rot19l(u8 o[ARIA_BLOCK_SIZE], const u8 xor[ARIA_BLOCK_SIZE], const u8* z[ARIA_BLOCK_SIZE])
{
    rotnr(8 * ARIA_BLOCK_SIZE - 19, o, xor, z);
}

/*
 * First substitution and xor layer, used for odd steps.
 * It is safe for the input and output to be the same.
 */
static void sl1(u8 o[ARIA_BLOCK_SIZE], const u8 x[ARIA_BLOCK_SIZE], const u8 y[ARIA_BLOCK_SIZE])
{
    unsigned int i;
    for (i = 0; i < ARIA_BLOCK_SIZE; i += 4) {
        o[i    ] = sb1[x[i    ] ^ y[i    ]];
        o[i + 1] = sb2[x[i + 1] ^ y[i + 1]];
        o[i + 2] = sb3[x[i + 2] ^ y[i + 2]];
        o[i + 3] = sb4[x[i + 3] ^ y[i + 3]];
    }
}

/*
 * Second substitution and xor layer, used for even steps.
 * It is safe for the input and output to be the same.
 */
static void sl2(u8 o[ARIA_BLOCK_SIZE], const u8 x[ARIA_BLOCK_SIZE], const u8 y[ARIA_BLOCK_SIZE])
{
    unsigned int i;
    for (i = 0; i < ARIA_BLOCK_SIZE; i += 4) {
        o[i    ] = sb3[x[i    ] ^ y[i    ]];
        o[i + 1] = sb4[x[i + 1] ^ y[i + 1]];
        o[i + 2] = sb1[x[i + 2] ^ y[i + 2]];
        o[i + 3] = sb2[x[i + 3] ^ y[i + 3]];
    }
}

/*
 * Diffusion layer step
 * It is NOT safe for the input and output to overlap.
 */
static void a(u8 y[ARIA_BLOCK_SIZE], const u8 x[16])
{
    y[ 0] = x[ 3] ^ x[ 4] ^ x[ 6] ^ x[ 8] ^
               x[ 9] ^ x[13] ^ x[14];
    y[ 1] = x[ 2] ^ x[ 5] ^ x[ 7] ^ x[ 8] ^
               x[ 9] ^ x[12] ^ x[15];
    y[ 2] = x[ 1] ^ x[ 4] ^ x[ 6] ^ x[10] ^
               x[11] ^ x[12] ^ x[15];
    y[ 3] = x[ 0] ^ x[ 5] ^ x[ 7] ^ x[10] ^
               x[11] ^ x[13] ^ x[14];
    y[ 4] = x[ 0] ^ x[ 2] ^ x[ 5] ^ x[ 8] ^
               x[11] ^ x[14] ^ x[15];
    y[ 5] = x[ 1] ^ x[ 3] ^ x[ 4] ^ x[ 9] ^
               x[10] ^ x[14] ^ x[15];
    y[ 6] = x[ 0] ^ x[ 2] ^ x[ 7] ^ x[ 9] ^
               x[10] ^ x[12] ^ x[13];
    y[ 7] = x[ 1] ^ x[ 3] ^ x[ 6] ^ x[ 8] ^
               x[11] ^ x[12] ^ x[13];
    y[ 8] = x[ 0] ^ x[ 1] ^ x[ 4] ^ x[ 7] ^
               x[10] ^ x[13] ^ x[15];
    y[ 9] = x[ 0] ^ x[ 1] ^ x[ 5] ^ x[ 6] ^
               x[11] ^ x[12] ^ x[14];
    y[10] = x[ 2] ^ x[ 3] ^ x[ 5] ^ x[ 6] ^
               x[ 8] ^ x[13] ^ x[15];
    y[11] = x[ 2] ^ x[ 3] ^ x[ 4] ^ x[ 7] ^
               x[ 9] ^ x[12] ^ x[14];
    y[12] = x[ 1] ^ x[ 2] ^ x[ 6] ^ x[ 7] ^
               x[ 9] ^ x[11] ^ x[12];
    y[13] = x[ 0] ^ x[ 3] ^ x[ 6] ^ x[ 7] ^
               x[ 8] ^ x[10] ^ x[13];
    y[14] = x[ 0] ^ x[ 3] ^ x[ 4] ^ x[ 5] ^
               x[ 9] ^ x[11] ^ x[14];
    y[15] = x[ 1] ^ x[ 2] ^ x[ 4] ^ x[ 5] ^
               x[ 8] ^ x[10] ^ x[15];
}

/*
 * Odd round function
 * Apply the first substitution layer and then a diffusion step.
 * It is safe for the input and output to overlap.
 */
static void FO(u8 o[ARIA_BLOCK_SIZE], const u8 d[ARIA_BLOCK_SIZE],
                           const u8 rk[ARIA_BLOCK_SIZE])
{
    u8 y[ARIA_BLOCK_SIZE];

    sl1(&y, d, rk);
    a(o, &y);
}

/*
 * Even round function
 * Apply the second substitution layer and then a diffusion step.
 * It is safe for the input and output to overlap.
 */
static void FE(u8 o[ARIA_BLOCK_SIZE], const u8 d[ARIA_BLOCK_SIZE],
                           const u8 rk[ARIA_BLOCK_SIZE])
{
    u8 y[ARIA_BLOCK_SIZE];

    sl2(y, d, rk);
    a(o, &y);
}