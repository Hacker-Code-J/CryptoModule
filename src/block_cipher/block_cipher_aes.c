/* File: src/block_cipher/block_cipher_aes.c */
/**
 * @file block_cipher_aes.c
 * @brief This file implements AES encryption and decryption operations.
 *
 * @note The implementation in this source code file references the following site:
 *       https://github.com/openssl/openssl/blob/master/crypto/aes/aes_core.c
 */

#include "../../include/block_cipher/block_cipher_aes.h"

/* Forward declarations of static functions. */
static block_cipher_status_t aes_init(BlockCipherContext *ctx, const u8 *key, size_t key_len, size_t block_len, BlockCipherDirection dir);
static block_cipher_status_t aes_process_block(BlockCipherContext *ctx, const u8 *in, u8 *out, BlockCipherDirection dir);
static void aes_dispose(BlockCipherContext *ctx);


// static block_cipher_status_t aes_process_single_block(BlockCipherContext *ctx, const u8 *key, size_t key_len, const u8 *input, u8 *output, int encrypt) {

// /**
//  * @brief AES encryption/decryption function for a single block.
//  * @param ctx Pointer to the block cipher context.
//  * @param key Pointer to the key.
//  * @param key_len Length of the key (AES128_KEY_SIZE, AES192_KEY_SIZE, or AES256_KEY_SIZE).
//  * @param input Pointer to the input data buffer.
//  * @param output Pointer to the output data buffer.
//  * @param encrypt Flag indicating encryption (ENCRYPTION_MODE) or decryption (DECRYPTION_MODE).
//  * @return Status of the operation.
//  */
// block_cipher_status_t aes_process_single_block(BlockCipherContext *ctx, const u8 *key, size_t key_len, const u8 *input, u8 *output, int encrypt) {
//     if (!ctx || !key || !input || !output) return BLOCK_CIPHER_ERR_INVALID_INPUT;

//     // Initialize the AES context
//     block_cipher_status_t status = aes_init(ctx, AES_BLOCK_SIZE, key, key_len, encrypt);
//     if (status != BLOCK_CIPHER_OK_INITIALIZATION) return status;

//     // Process the single block
//     status = aes_process_block(ctx, input, output, encrypt);
//     if (status != BLOCK_CIPHER_OK_ENCRYPTION && status != BLOCK_CIPHER_OK_DECRYPTION) return status;

//     return BLOCK_CIPHER_OK_PROCESS;
// }

block_cipher_status_t aes_set_encrypt_key(const u8 *key, size_t bytes, u32 *rk);
block_cipher_status_t aes_set_decrypt_key(const u8 *key, size_t bytes, u32 *rk);
block_cipher_status_t aes_encrypt(const u8 *in, u8 *out, const u32 *rk, int r);
block_cipher_status_t aes_decrypt(const u8 *in, u8 *out, const u32 *rk, int r);

/**
 * @brief The AES block cipher API.
 * @details This structure contains function pointers to the AES initialization, unified encryption/decryption function,
 *          and disposal functions.
 */
static const BlockCipherApi AES_API = {
    .name          = "AES",
    .init          = aes_init,
    .process_block = aes_process_block,
    .dispose       = aes_dispose
};

/**
 * @brief Get the AES block cipher API.
 * @return Pointer to the AES block cipher API structure.
 * @details This function returns a pointer to the AES block cipher API structure,
 *          which contains function pointers for AES operations.
 */
const BlockCipherApi *get_aes_api(void) { return &AES_API; }

block_cipher_status_t aes_set_encrypt_key(const u8 *key, size_t bytes, u32 *rk) {
    if (!key || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    
    int i = 0;
    u32 temp;

    rk[0] = GETU32(key     );
    rk[1] = GETU32(key +  4);
    rk[2] = GETU32(key +  8);
    rk[3] = GETU32(key + 12);
    if (bytes == AES128_KEY_SIZE) {
        while (1) {
            temp  = rk[3];
            rk[4] = rk[0] ^
                (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te0[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te1[(temp >> 24)       ] & 0x000000ff) ^
                rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
                return BLOCK_CIPHER_OK_KEY_EXPANSION;
            }
            rk += 4;
        }
    }
    rk[4] = GETU32(key + 16);
    rk[5] = GETU32(key + 20);
    if (bytes == AES192_KEY_SIZE) {
        while (1) {
            temp = rk[ 5];
            rk[ 6] = rk[ 0] ^
                (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te0[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te1[(temp >> 24)       ] & 0x000000ff) ^
                rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8) {
                return 0;
            }
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
    }
    rk[6] = GETU32(key + 24);
    rk[7] = GETU32(key + 28);
    if (bytes == AES256_KEY_SIZE) {
        while (1) {
            temp = rk[ 7];
            rk[ 8] = rk[ 0] ^
                (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te0[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te1[(temp >> 24)       ] & 0x000000ff) ^
                rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7) {
                return BLOCK_CIPHER_OK_KEY_EXPANSION;
            }
            temp = rk[11];
            rk[12] = rk[ 4] ^
                (Te2[(temp >> 24)       ] & 0xff000000) ^
                (Te3[(temp >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(temp >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(temp      ) & 0xff] & 0x000000ff);
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];

            rk += 8;
            }
    }

    // u32 temp;
    // size_t i, n;

    // n = bytes / 4;

    // for (i = 0; i < n; i++) { rk[i] = GETU32(key + (i * 4)); }
    // for (i = n; i < ((n + 6) + 1) * 4; i++) {
    //     temp = rk[i - 1];
    //     if (i % n == 0) { temp = sub_word(rotate_word(temp)) ^ rcon[i / n - 1]; } 
    //     else if ((n > 6) && (i % n == 4)) { temp = sub_word(temp); }
    //     rk[i] = rk[i - n] ^ temp;
    // }

    // printf("Encryption Key Schedule:\n");
    // for (i=0; i < ((n + 6) + 1) * 4; i++) {
    //     printf("%08x:", rk[i]);
    //     if (i % 4 == 3) printf("\n");
    // }
    return BLOCK_CIPHER_OK_KEY_EXPANSION;
}

block_cipher_status_t aes_set_decrypt_key(const u8 *key, size_t bytes, u32 *rk) {
    if (!key || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    
    int i, j, nr;
    u32 temp;
    block_cipher_status_t status;

    switch (bytes) {
        case AES128_KEY_SIZE: nr = AES128_NUM_ROUNDS; break;
        case AES192_KEY_SIZE: nr = AES192_NUM_ROUNDS; break;
        case AES256_KEY_SIZE: nr = AES256_NUM_ROUNDS; break;
        default: return BLOCK_CIPHER_ERR_INVALID_KEY_SIZE;
    }

    status = aes_set_encrypt_key(key, bytes, rk);
    if (status != BLOCK_CIPHER_OK_KEY_EXPANSION) {
        return BLOCK_CIPHER_ERR_KEY_EXPANSION;
    }

    /* invert the order of round keys */
    for (i = 0, j = 4 * nr; i < j; i += 4, j -= 4) {
        temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
        temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
        temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
        temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
    }

    for (i = 1; i < nr; i++) {
        rk += 4;
        rk[0] = 
            Td0[Te1[(rk[0] >> 24)       ] & 0xff] ^
            Td1[Te1[(rk[0] >> 16) & 0xff] & 0xff] ^
            Td2[Te1[(rk[0] >>  8) & 0xff] & 0xff] ^
            Td3[Te1[(rk[0]      ) & 0xff] & 0xff];
        rk[1] =
            Td0[Te1[(rk[1] >> 24)       ] & 0xff] ^
            Td1[Te1[(rk[1] >> 16) & 0xff] & 0xff] ^
            Td2[Te1[(rk[1] >>  8) & 0xff] & 0xff] ^
            Td3[Te1[(rk[1]      ) & 0xff] & 0xff];
        rk[2] =
            Td0[Te1[(rk[2] >> 24)       ] & 0xff] ^
            Td1[Te1[(rk[2] >> 16) & 0xff] & 0xff] ^
            Td2[Te1[(rk[2] >>  8) & 0xff] & 0xff] ^
            Td3[Te1[(rk[2]      ) & 0xff] & 0xff];
        rk[3] = 
            Td0[Te1[(rk[3] >> 24)       ] & 0xff] ^
            Td1[Te1[(rk[3] >> 16) & 0xff] & 0xff] ^
            Td2[Te1[(rk[3] >>  8) & 0xff] & 0xff] ^
            Td3[Te1[(rk[3]      ) & 0xff] & 0xff];
    }
    return BLOCK_CIPHER_OK_KEY_EXPANSION;
}

block_cipher_status_t aes_init(BlockCipherContext *ctx, const u8 *key, size_t key_len, size_t block_len, BlockCipherDirection dir) {
    if (!ctx || !key) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    if (block_len != AES_BLOCK_SIZE) return BLOCK_CIPHER_ERR_INVALID_BLOCK_SIZE;
    if (key_len != AES128_KEY_SIZE && 
        key_len != AES192_KEY_SIZE && 
        key_len != AES256_KEY_SIZE) return BLOCK_CIPHER_ERR_INVALID_KEY_SIZE;

    ctx->internal_data.aes_internal.block_size = block_len;
    ctx->internal_data.aes_internal.key_len = key_len;
    switch(key_len) {
        case AES128_KEY_SIZE: ctx->internal_data.aes_internal.nr = AES128_NUM_ROUNDS; break;
        case AES192_KEY_SIZE: ctx->internal_data.aes_internal.nr = AES192_NUM_ROUNDS; break;
        case AES256_KEY_SIZE: ctx->internal_data.aes_internal.nr = AES256_NUM_ROUNDS; break;
    }
    memset(ctx->internal_data.aes_internal.round_keys, 0,
           sizeof(ctx->internal_data.aes_internal.round_keys));

    /* Key expansion */
    block_cipher_status_t status;
    switch (dir) {
        case BLOCK_CIPHER_ENCRYPTION:
            if (aes_set_encrypt_key(key, key_len, ctx->internal_data.aes_internal.round_keys) != BLOCK_CIPHER_OK_KEY_EXPANSION)
                status = BLOCK_CIPHER_ERR_INITIALIZATION;
            else status = BLOCK_CIPHER_OK_INITIALIZATION;
            break;
        case BLOCK_CIPHER_DECRYPTION:
            if (aes_set_decrypt_key(key, key_len, ctx->internal_data.aes_internal.round_keys) != BLOCK_CIPHER_OK_KEY_EXPANSION)
                status = BLOCK_CIPHER_ERR_INITIALIZATION;
            else status = BLOCK_CIPHER_OK_INITIALIZATION;
            break;
        default:
            status = BLOCK_CIPHER_ERR_INVALID_MODE;
            break;
    }

    return status;
}

block_cipher_status_t aes_encrypt(const u8 *in, u8 *out, const u32 *rk, int r) {
    if (!in || !out || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    
    u32 s0, s1, s2, s3, t0, t1, t2, t3;

    // for (int i = 0; i < AES128_NUM_ROUNDS + 1; i++) {
    //     printf("%08X:%08X:%08X:%08X\n", rk[i * 4], rk[i * 4 + 1], rk[i * 4 + 2], rk[i * 4 + 3]);
    // }

    /* map byte array block to cipher state and add initial round key: */
    s0 = GETU32(in +  0) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];
    // printf("[+RK] %08X:%08X:%08X:%08X\n", s0, s1, s2, s3);

    /* apply round keys and main rounds: */
    /* round 1: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
    // printf("[R01] %08X:%08X:%08X:%08X\n", t0, t1, t2, t3);
    /* round 2: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
    // printf("[R02] %08X:%08X:%08X:%08X\n", s0, s1, s2, s3);
    /* round 3: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
    // printf("[R03] %08X:%08X:%08X:%08X\n", t0, t1, t2, t3);
    /* round 4: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
    // printf("[R04] %08X:%08X:%08X:%08X\n", s0, s1, s2, s3);
    /* round 5: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
    // printf("[R05] %08X:%08X:%08X:%08X\n", t0, t1, t2, t3);
    /* round 6: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
    // printf("[R06] %08X:%08X:%08X:%08X\n", s0, s1, s2, s3);
    /* round 7: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
    // printf("[R07] %08X:%08X:%08X:%08X\n", t0, t1, t2, t3);
    /* round 8: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
    // printf("[R08] %08X:%08X:%08X:%08X\n", s0, s1, s2, s3);
    /* round 9: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
    // printf("[R09] %08X:%08X:%08X:%08X\n", t0, t1, t2, t3);
    if (r > AES128_NUM_ROUNDS) {
        /* round 10: */
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
        // printf("[R10] %08X:%08X:%08X:%08X\n", s0, s1, s2, s3);
        /* round 11: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
        // printf("[R11] %08X:%08X:%08X:%08X\n", t0, t1, t2, t3);
        if (r > AES192_NUM_ROUNDS) {
            /* round 12: */
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
            // printf("[R12] %08X:%08X:%08X:%08X\n", s0, s1, s2, s3);
            /* round 13: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
            // printf("[R13] %08X:%08X:%08X:%08X\n", t0, t1, t2, t3);
        }
    }
    rk += r << 2;
    s0 =
        (Te2[(t0 >> 24)       ] & 0xff000000) ^
        (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
        (Te1[(t3      ) & 0xff] & 0x000000ff) ^
        rk[0];
    s1 =
        (Te2[(t1 >> 24)       ] & 0xff000000) ^
        (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
        (Te1[(t0      ) & 0xff] & 0x000000ff) ^
        rk[1];
    s2 =
        (Te2[(t2 >> 24)       ] & 0xff000000) ^
        (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
        (Te1[(t1      ) & 0xff] & 0x000000ff) ^
        rk[2];
    s3 =
        (Te2[(t3 >> 24)       ] & 0xff000000) ^
        (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
        (Te1[(t2      ) & 0xff] & 0x000000ff) ^
        rk[3];
    PUTU32(out     , s0);
    PUTU32(out +  4, s1);
    PUTU32(out +  8, s2);
    PUTU32(out + 12, s3);

    // printf("AES encrypt: ");
    // for (i = 0; i < st->key_len; i++) {
    //     printf("%08x:", out[i]);
    //     if (i % 4 == 3) printf("\n");
    // }
    return BLOCK_CIPHER_OK_ENCRYPTION;
}

block_cipher_status_t aes_decrypt(const u8 *in, u8 *out, const u32 *rk, int r) {
    if (!in || !out || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    /* map byte array block to cipher state and add initial round key: */
    s0 = GETU32(in +  0) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];
    /* apply round keys and main rounds: */
    /* round 1: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[ 4];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[ 5];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[ 6];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[ 7];
    /* round 2: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[ 8];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[ 9];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[10];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[11];
    /* round 3: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[12];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[13];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[14];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[15];
    /* round 4: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[16];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[17];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[18];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[19];
    /* round 5: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[20];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[21];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[22];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[23];
    /* round 6: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[24];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[25];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[26];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[27];
    /* round 7: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[28];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[29];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[30];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[31];
    /* round 8: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[32];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[33];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[34];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[35];
    /* round 9: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[36];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[37];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[38];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[39];
    if (r > 10) {
        /* round 10: */
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[40];
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[41];
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[42];
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[43];
        /* round 11: */
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[44];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[45];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[46];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[47];
        if (r > 12) {
            /* round 12: */
            s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[48];
            s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[49];
            s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[50];
            s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[51];
            /* round 13: */
            t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[52];
            t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[53];
            t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[54];
            t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[55];
        }
    }
    rk += r << 2;
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
        ((u32)Td4[(t0 >> 24)       ] << 24) ^
        ((u32)Td4[(t3 >> 16) & 0xff] << 16) ^
        ((u32)Td4[(t2 >>  8) & 0xff] <<  8) ^
        ((u32)Td4[(t1      ) & 0xff])       ^
        rk[0];
    s1 =
        ((u32)Td4[(t1 >> 24)       ] << 24) ^
        ((u32)Td4[(t0 >> 16) & 0xff] << 16) ^
        ((u32)Td4[(t3 >>  8) & 0xff] <<  8) ^
        ((u32)Td4[(t2      ) & 0xff])       ^
        rk[1];
    s2 =
        ((u32)Td4[(t2 >> 24)       ] << 24) ^
        ((u32)Td4[(t1 >> 16) & 0xff] << 16) ^
        ((u32)Td4[(t0 >>  8) & 0xff] <<  8) ^
        ((u32)Td4[(t3      ) & 0xff])       ^
        rk[2];
    s3 =
        ((u32)Td4[(t3 >> 24)       ] << 24) ^
        ((u32)Td4[(t2 >> 16) & 0xff] << 16) ^
        ((u32)Td4[(t1 >>  8) & 0xff] <<  8) ^
        ((u32)Td4[(t0      ) & 0xff])       ^
        rk[3];

    PUTU32(out     , s0);
    PUTU32(out +  4, s1);   
    PUTU32(out +  8, s2);
    PUTU32(out + 12, s3);
    
    // printf("AES decrypt: ");
    // for (i = 0; i < st->key_len; i++) {
    //     printf("%08x:", out[i]);
    //     if (i % 4 == 3) printf("\n");
    // }
    
    return BLOCK_CIPHER_OK_DECRYPTION;
}

block_cipher_status_t aes_process_block(BlockCipherContext *ctx, const u8 *in, u8 *out, BlockCipherDirection dir) {
    if (!ctx || !in || !out) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    
    switch (dir) {
        case BLOCK_CIPHER_ENCRYPTION:
            return aes_encrypt(in, out, ctx->internal_data.aes_internal.round_keys, ctx->internal_data.aes_internal.nr);
        case BLOCK_CIPHER_DECRYPTION:
            return aes_decrypt(in, out, ctx->internal_data.aes_internal.round_keys, ctx->internal_data.aes_internal.nr);
        default:
            return BLOCK_CIPHER_ERR_INVALID_DIRECTION;
    }
}

void aes_dispose(BlockCipherContext *ctx) {
    if (!ctx) return;
    /* Clear out the AES portion of the union. */
    memset(&ctx->internal_data.aes_internal, 0,
           sizeof(ctx->internal_data.aes_internal));
}