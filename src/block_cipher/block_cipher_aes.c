/* File: src/block_cipher/block_cipher_aes.c */
#include "../../include/block_cipher/block_cipher_aes.h"

/* Forward declarations of static functions. */
static block_cipher_status_t aes_init(BlockCipherContext *ctx, const u8 *key, size_t block_size, size_t key_len, int encrypt);
static block_cipher_status_t aes_process_block(BlockCipherContext *ctx, const u8 *input, u8 *output, int encrypt);
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

block_cipher_status_t aes_enc_key_expansion(const u8 *in, u32 *out, size_t bytes);
block_cipher_status_t aes_dec_key_expansion(const u8 *in, u32 *out, size_t bytes);
block_cipher_status_t aes_set_encrypt_key(const u8 *key, size_t bytes, u32 *rk);
block_cipher_status_t aes_set_decrypt_key(const u8 *key, size_t bytes, u32 *rk);
block_cipher_status_t aes_encrypt(const u8 *in, u8 *out, const u32 *rk, int r);
block_cipher_status_t aes_decrypt(const u8 *in, u8 *out, const u32 *rk, int r);

// static block_cipher_status_t aes_dispose(BlockCipherContext *ctx) {
//     if (!ctx) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
//     // Zero out sensitive data
//     memset(ctx->internal_data.aes_internal.round_keys, 0, sizeof(ctx->internal_data.aes_internal.round_keys));
//     return BLOCK_CIPHER_OK_DISPOSE;
// }
// static block_cipher_status_t aes_process_block(BlockCipherContext *ctx, const u8 *input, u8 *output, int encrypt);
// static block_cipher_status_t aes_process_block(BlockCipherContext *ctx, const u8 *input, u8 *output, int encrypt) {
//     if (!ctx || !input || !output) return BLOCK_CIPHER_ERR_INVALID_INPUT;

//     switch (encrypt) {
//         case ENCRYPTION_MODE:
//             aes_encrypt(input, output, ctx->internal_data.aes_internal.round_keys, ctx->internal_data.aes_internal.nr);
//             break;
//         case DECRYPTION_MODE:
//             aes_decrypt(input, output, ctx->internal_data.aes_internal.round_keys, ctx->internal_data.aes_internal.nr);
//             break;
//         default:
//             return BLOCK_CIPHER_ERR_INVALID_MODE;
//     }
//     return BLOCK_CIPHER_OK_ENCRYPTION;
// }
// static block_cipher_status_t aes_dispose(BlockCipherContext *ctx) {
//     if (!ctx) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
//     // Zero out sensitive data
//     memset(ctx->internal_data.aes_internal.round_keys, 0, sizeof(ctx->internal_data.aes_internal.round_keys));
//     return BLOCK_CIPHER_OK_DISPOSE;
// }
// static block_cipher_status_t aes_set_encrypt_key(const u8 *key, int bytes, u32 *rk);
// static block_cipher_status_t aes_set_encrypt_key(const u8 *key, int bytes, u32 *rk) {
//     if (!key || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
//     if (bytes != AES128_KEY_SIZE && 
//         bytes != AES192_KEY_SIZE && 
//         bytes != AES256_KEY_SIZE) return BLOCK_CIPHER_ERR_INVALID_KEY_LENGTH;

//     return aes_enc_key_expansion(key, rk, bytes);
// }
// static block_cipher_status_t aes_set_decrypt_key(const u32 *key, int bytes, u32 *rk);
// static block_cipher_status_t aes_set_decrypt_key(const u32 *key, int bytes, u32 *rk) {
//     if (!key || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
//     if (bytes != AES128_KEY_SIZE && 
//         bytes != AES192_KEY_SIZE && 
//         bytes != AES256_KEY_SIZE) return BLOCK_CIPHER_ERR_INVALID_KEY_LENGTH;

//     return aes_dec_key_expansion(key, rk, bytes);
// }
// static block_cipher_status_t aes_encrypt(const u8 *in, u8 *out, const u32 *rk, int r);
// static block_cipher_status_t aes_encrypt(const u8 *in, u8 *out, const u32 *rk, int r) {
//     if (!in || !out || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;

//     // AES encryption logic goes here
//     // For example, you can use the AES encryption functions from the original rijndael-alg-fst.c
//     // This is a placeholder for the actual AES encryption logic.
//     // Example:
//     // AES_encrypt(in, out, rk, r);
//     return BLOCK_CIPHER_OK_ENCRYPTION;
// }
// static block_cipher_status_t aes_decrypt(const u8 *in, u8 *out, const u32 *rk, int r);
// static block_cipher_status_t aes_decrypt(const u8 *in, u8 *out, const u32 *rk, int r) {
//     if (!in || !out || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;

//     // AES decryption logic goes here
//     // For example, you can use the AES decryption functions from the original rijndael-alg-fst.c
//     // This is a placeholder for the actual AES decryption logic.
//     // Example:
//     // AES_decrypt(in, out, rk, r);
//     return BLOCK_CIPHER_OK_DECRYPTION;
// }

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

block_cipher_status_t aes_enc_key_expansion(const u8 *in, u32 *out, size_t bytes) {
    u32 temp;
    size_t i, n;

    n = bytes / 4;

    for (i = 0; i < n; i++) { out[i] = GETU32(in + (i * 4)); }
    for (i = n; i < ((n + 6) + 1) * 4; i++) {
        temp = out[i - 1];
        if (i % n == 0) { temp = sub_word(rotate_word(temp)) ^ rcon[i / n - 1]; } 
        else if ((n > 6) && (i % n == 4)) { temp = sub_word(temp); }
        out[i] = out[i - n] ^ temp;
    }

    // for (i=0; i < ((n + 6) + 1) * 4; i++) {
    //     printf("%08x:", out[i]);
    //     if (i % 4 == 3) printf("\n");
    // }
    return BLOCK_CIPHER_OK_KEY_EXPANSION;
}

block_cipher_status_t aes_dec_key_expansion(const u8 *in, u32 *out, size_t bytes) {
    int nr; 
    int i, j;
    u32 temp;
    
    if (aes_enc_key_expansion(in, out, bytes) != BLOCK_CIPHER_OK_KEY_EXPANSION) {
        return BLOCK_CIPHER_ERR_KEY_EXPANSION;
    }
    
    switch (bytes) {
        case AES128_KEY_SIZE: nr = AES128_NUM_ROUNDS; break;
        case AES192_KEY_SIZE: nr = AES192_NUM_ROUNDS; break;
        case AES256_KEY_SIZE: nr = AES256_NUM_ROUNDS; break;
        default: return BLOCK_CIPHER_ERR_INVALID_KEY_SIZE;
    }

    for (i = 0, j = 4 * nr; i < j; i += 4, j -= 4) {
        temp = out[i    ]; out[i    ] = out[j    ]; out[j    ] = temp;
        temp = out[i + 1]; out[i + 1] = out[j + 1]; out[j + 1] = temp;
        temp = out[i + 2]; out[i + 2] = out[j + 2]; out[j + 2] = temp;
        temp = out[i + 3]; out[i + 3] = out[j + 3]; out[j + 3] = temp;
    }

    for (i = 1; i < nr; i++) {
        out += 4;
        out[0] = 
            Td0[Te1[out[0] >> 24       ]] ^
            Td1[Te2[out[1] >> 16 & 0xff]] ^
            Td2[Te3[out[2] >> 8  & 0xff]] ^
            Td3[Te0[out[3]       & 0xff]];
        out[1] =
            Td0[Te1[out[1] >> 24       ]] ^
            Td1[Te2[out[2] >> 16 & 0xff]] ^
            Td2[Te3[out[3] >> 8  & 0xff]] ^
            Td3[Te0[out[0]       & 0xff]];
        out[2] =    
            Td0[Te1[out[2] >> 24       ]] ^
            Td1[Te2[out[3] >> 16 & 0xff]] ^
            Td2[Te3[out[0] >> 8  & 0xff]] ^
            Td3[Te0[out[1]       & 0xff]];
        out[3] =
            Td0[Te1[out[3] >> 24       ]] ^
            Td1[Te2[out[0] >> 16 & 0xff]] ^
            Td2[Te3[out[1] >> 8  & 0xff]] ^
            Td3[Te0[out[2]       & 0xff]];
    }

    return BLOCK_CIPHER_OK_KEY_EXPANSION;
}

block_cipher_status_t aes_set_encrypt_key(const u8 *key, size_t bytes, u32 *rk) {
    if (!key || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    if (bytes != AES128_KEY_SIZE && 
        bytes != AES192_KEY_SIZE && 
        bytes != AES256_KEY_SIZE) return BLOCK_CIPHER_ERR_INVALID_KEY_SIZE;
    return aes_enc_key_expansion(key, rk, bytes);
}

block_cipher_status_t aes_set_decrypt_key(const u8 *key, size_t bytes, u32 *rk) {
    if (!key || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    if (bytes != AES128_KEY_SIZE && 
        bytes != AES192_KEY_SIZE && 
        bytes != AES256_KEY_SIZE) return BLOCK_CIPHER_ERR_INVALID_KEY_SIZE;
    return aes_dec_key_expansion(key, rk, bytes);
}

block_cipher_status_t aes_init(BlockCipherContext *ctx, const u8 *key, size_t block_size, size_t key_len, int encrypt) {
    if (!ctx || !key) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    if (block_size != AES_BLOCK_SIZE) return BLOCK_CIPHER_ERR_INVALID_BLOCK_SIZE;
    if (key_len != AES128_KEY_SIZE && 
        key_len != AES192_KEY_SIZE && 
        key_len != AES256_KEY_SIZE) return BLOCK_CIPHER_ERR_INVALID_KEY_SIZE;

    ctx->api = get_aes_api(); /* Link the context to the vtable. */
    if (!ctx->api) {
        return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION; /* internal_data is not properly allocated */
    }
    memset(ctx, 0, sizeof(*ctx)); /* Initialize the context. */

    ctx->internal_data.aes_internal.block_size = block_size;
    ctx->internal_data.aes_internal.key_len = key_len;
    switch(key_len) {
        case AES128_KEY_SIZE: ctx->internal_data.aes_internal.nr = AES128_NUM_ROUNDS; break;
        case AES192_KEY_SIZE: ctx->internal_data.aes_internal.nr = AES192_NUM_ROUNDS; break;
        case AES256_KEY_SIZE: ctx->internal_data.aes_internal.nr = AES256_NUM_ROUNDS; break;
    }
    memset(ctx->internal_data.aes_internal.round_keys, 0,
           sizeof(ctx->internal_data.aes_internal.round_keys));

    /* Key expansion */
    switch (encrypt) {
        case ENCRYPTION_MODE:
            if (aes_enc_key_expansion(key, ctx->internal_data.aes_internal.round_keys, key_len) != BLOCK_CIPHER_OK_KEY_EXPANSION) {
                return BLOCK_CIPHER_ERR_INITIALIZATION;
            } else {
                return BLOCK_CIPHER_OK_INITIALIZATION;
            }
        case DECRYPTION_MODE:
            if (aes_dec_key_expansion(key, ctx->internal_data.aes_internal.round_keys, key_len) != BLOCK_CIPHER_OK_KEY_EXPANSION) {
                return BLOCK_CIPHER_ERR_INITIALIZATION;
            } else {
                return BLOCK_CIPHER_OK_INITIALIZATION;
            }
        default:
            return BLOCK_CIPHER_ERR_INVALID_MODE;
    }
}

block_cipher_status_t aes_encrypt(const u8 *in, u8 *out, const u32 *rk, int r) {
    if (!in || !out || !rk) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    
    u32 s0, s1, s2, s3, t0, t1, t2, t3;

    /* map byte array block to cipher state and add initial round key: */
    s0 = GETU32(in +  0) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];
    /* apply round keys and main rounds: */
    r = r >> 1; // AES rounds are halved for encryption
    for (;;) {
        t0 = Te0[s0 >> 24] ^ Te1[s1 >> 16 & 0xff] ^ Te2[s2 >> 8 & 0xff] ^ Te3[s3 & 0xff] ^ rk[4];
        t1 = Te0[s1 >> 24] ^ Te1[s2 >> 16 & 0xff] ^ Te2[s3 >> 8 & 0xff] ^ Te3[s0 & 0xff] ^ rk[5];
        t2 = Te0[s2 >> 24] ^ Te1[s3 >> 16 & 0xff] ^ Te2[s0 >> 8 & 0xff] ^ Te3[s1 & 0xff] ^ rk[6];
        t3 = Te0[s3 >> 24] ^ Te1[s0 >> 16 & 0xff] ^ Te2[s1 >> 8 & 0xff] ^ Te3[s2 & 0xff] ^ rk[7];
        
        rk += 8;
        if (--r == 0) break;

        s0 = Te0[t0 >> 24] ^ Te1[t1 >> 16 & 0xff] ^ Te2[t2 >> 8 & 0xff] ^ Te3[t3 & 0xff] ^ rk[0];
        s1 = Te0[t1 >> 24] ^ Te1[t2 >> 16 & 0xff] ^ Te2[t3 >> 8 & 0xff] ^ Te3[t0 & 0xff] ^ rk[1];
        s2 = Te0[t2 >> 24] ^ Te1[t3 >> 16 & 0xff] ^ Te2[t0 >> 8 & 0xff] ^ Te3[t1 & 0xff] ^ rk[2];
        s3 = Te0[t3 >> 24] ^ Te1[t0 >> 16 & 0xff] ^ Te2[t1 >> 8 & 0xff] ^ Te3[t2 & 0xff] ^ rk[3];
    }

    s0 = (Te2[s0 >> 24] & 0xff000000) ^ (Te3[s1 >> 16 & 0xff] & 0x00ff0000) ^ (Te0[s2 >> 8 & 0xff] & 0x0000ff00) ^ (Te1[s3 & 0xff] & 0x000000ff) ^ rk[0];
    s1 = (Te2[s1 >> 24] & 0xff000000) ^ (Te3[s2 >> 16 & 0xff] & 0x00ff0000) ^ (Te0[s3 >> 8 & 0xff] & 0x0000ff00) ^ (Te1[s0 & 0xff] & 0x000000ff) ^ rk[1];
    s2 = (Te2[s2 >> 24] & 0xff000000) ^ (Te3[s3 >> 16 & 0xff] & 0x00ff0000) ^ (Te0[s0 >> 8 & 0xff] & 0x0000ff00) ^ (Te1[s1 & 0xff] & 0x000000ff) ^ rk[2];
    s3 = (Te2[s3 >> 24] & 0xff000000) ^ (Te3[s0 >> 16 & 0xff] & 0x00ff0000) ^ (Te0[s1 >> 8 & 0xff] & 0x0000ff00) ^ (Te1[s2 & 0xff] & 0x000000ff) ^ rk[3];
    /* map cipher state to byte array block: */
    PUTU32(out +  0, s0);
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
    r = r >> 1; // AES rounds are halved for decryption
    for (;;) {
        t0 = Td0[s0 >> 24] ^ Td1[s1 >> 16 & 0xff] ^ Td2[s2 >> 8 & 0xff] ^ Td3[s3 & 0xff] ^ rk[4];
        t1 = Td0[s1 >> 24] ^ Td1[s2 >> 16 & 0xff] ^ Td2[s3 >> 8 & 0xff] ^ Td3[s0 & 0xff] ^ rk[5];
        t2 = Td0[s2 >> 24] ^ Td1[s3 >> 16 & 0xff] ^ Td2[s0 >> 8 & 0xff] ^ Td3[s1 & 0xff] ^ rk[6];
        t3 = Td0[s3 >> 24] ^ Td1[s0 >> 16 & 0xff] ^ Td2[s1 >> 8 & 0xff] ^ Td3[s2 & 0xff] ^ rk[7];
        
        rk += 8;
        if (--r == 0) break;

        s0 = Td0[t0 >> 24] ^ Td1[t1 >> 16 & 0xff] ^ Td2[t2 >> 8 & 0xff] ^ Td3[t3 & 0xff] ^ rk[0];
        s1 = Td0[t1 >> 24] ^ Td1[t2 >> 16 & 0xff] ^ Td2[t3 >> 8 & 0xff] ^ Td3[t0 & 0xff] ^ rk[1];
        s2 = Td0[t2 >> 24] ^ Td1[t3 >> 16 & 0xff] ^ Td2[t0 >> 8 & 0xff] ^ Td3[t1 & 0xff] ^ rk[2];
        s3 = Td0[t3 >> 24] ^ Td1[t0 >> 16 & 0xff] ^ Td2[t1 >> 8 & 0xff] ^ Td3[t2 & 0xff] ^ rk[3];
    }
    s0 = ((u32)Td4[(t0 >> 24)] << 24) ^ ((u32)Td4[(t3 >> 16) & 0xff] << 16) ^ ((u32)Td4[(t2 >> 8) & 0xff] << 8) ^ ((u32)Td4[t1 & 0xff]) ^ rk[0];
    s1 = ((u32)Td4[(t1 >> 24)] << 24) ^ ((u32)Td4[(t0 >> 16) & 0xff] << 16) ^ ((u32)Td4[(t3 >> 8) & 0xff] << 8) ^ ((u32)Td4[t2 & 0xff]) ^ rk[1];
    s2 = ((u32)Td4[(t2 >> 24)] << 24) ^ ((u32)Td4[(t1 >> 16) & 0xff] << 16) ^ ((u32)Td4[(t0 >> 8) & 0xff] << 8) ^ ((u32)Td4[t3 & 0xff]) ^ rk[2];
    s3 = ((u32)Td4[(t3 >> 24)] << 24) ^ ((u32)Td4[(t2 >> 16) & 0xff] << 16) ^ ((u32)Td4[(t1 >> 8) & 0xff] << 8) ^ ((u32)Td4[t0 & 0xff]) ^ rk[3];
    /* map cipher state to byte array block: */
    PUTU32(out +  0, s0);
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

block_cipher_status_t aes_process_block(BlockCipherContext *ctx, const u8 *input, u8 *output, int encrypt) {
    if (!ctx || !input || !output) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
    
    switch(encrypt) {
        case ENCRYPTION_MODE:
            return aes_encrypt(input, output, ctx->internal_data.aes_internal.round_keys, ctx->internal_data.aes_internal.nr);
        case DECRYPTION_MODE:
            return aes_decrypt(input, output, ctx->internal_data.aes_internal.round_keys, ctx->internal_data.aes_internal.nr);
        default:
            return BLOCK_CIPHER_ERR_INVALID_MODE;
    }
}

// static block_cipher_status_t aes_dispose(BlockCipherContext *ctx) {
//     if (!ctx) return BLOCK_CIPHER_ERR_MEMORY_ALLOCATION;
//     // Zero out sensitive data
//     memset(ctx->internal_data.aes_internal.round_keys, 0, sizeof(ctx->internal_data.aes_internal.round_keys));
//     return BLOCK_CIPHER_OK_DISPOSE;
// }
static void aes_dispose(BlockCipherContext *ctx) {
    if (!ctx) return;
    // Zero out sensitive data
    memset(ctx->internal_data.aes_internal.round_keys, 0, sizeof(ctx->internal_data.aes_internal.round_keys));
    // Dispose of the context
    if (ctx->api && ctx->api->dispose) {
        ctx->api->dispose(ctx);
    }
    ctx->api = NULL;
    ctx->internal_data.aes_internal.block_size = 0;
    ctx->internal_data.aes_internal.key_len = 0;
    ctx->internal_data.aes_internal.nr = 0;
    memset(ctx->internal_data.aes_internal.round_keys, 0, sizeof(ctx->internal_data.aes_internal.round_keys));


    // if (!ctx) return;
    // Clear the key material in aes_internal
    // memset(&ctx->internal_data.aes_internal, 0,
    // sizeof(ctx->internal_data.aes_internal));
}

// /* Forward declarations of static functions. */
// static int  aes_init(BlockCipherContext *ctx, size_t block_size, const u8 *key, size_t key_len);
// static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct);
// static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt);
// static void aes_dispose(BlockCipherContext *ctx);

// /* The global vtable for AES. */

// /**
//  * @brief The AES block cipher API.
//  * @details This structure contains function pointers to the AES encryption and decryption functions,
//  *          as well as the initialization and disposal functions.
//  */
// static const BlockCipherApi AES_API = {
//     .name          = "AES",
//     .init          = aes_init,
//     .encrypt_block = aes_encrypt,
//     .decrypt_block = aes_decrypt,
//     .dispose       = aes_dispose
// };

// /**
//  * @brief Get the AES block cipher API.
//  * @return Pointer to the AES block cipher API structure.
//  * @details This function returns a pointer to the AES block cipher API structure,
//  *          which contains function pointers for AES encryption and decryption operations.
//  */
// const BlockCipherApi *get_aes_api(void) { return &AES_API; }


/* ********** Implementation of the function pointers ********** */
// static int aes_init(BlockCipherContext *ctx, size_t block_size, const u8 *key, size_t key_len) {
//     if (!ctx || !key) return -1;
//     if (block_size != AES_BLOCK_SIZE) return -1; /* AES typically 128-bit block size */
//     if (key_len != AES128_KEY_SIZE && 
//         key_len != AES192_KEY_SIZE && 
//         key_len != AES256_KEY_SIZE) {
//         return -1; /* only AES-128, 192, or 256 */
//     }

//     ctx->api = get_aes_api(); /* Link the context to the vtable. */
//     if (!ctx->api) {
//         return -1; /* internal_data is not properly allocated */
//     }
//     memset(ctx, 0, sizeof(*ctx)); /* Initialize the context. */

//     /* Our AES sub-struct is 'aes_internal' inside the union. */
//     ctx->internal_data.aes_internal.block_size = block_size;
//     ctx->internal_data.aes_internal.key_len    = key_len;
//     memset(ctx->internal_data.aes_internal.round_keys, 0,
//     sizeof(ctx->internal_data.aes_internal.round_keys));

//     /* Suppose we do a real key expansion here... */
//     // e.g. compute round_keys, set nr=10 for AES-128, etc.
//     // We'll just store nr = 10 if key_len=16, 12 if key_len=24, 14 if key_len=32.

//     aes_enc_key_expansion(ctx, key, ctx->internal_data.aes_internal.round_keys);
//     switch(key_len) {
//         case AES128_KEY_SIZE: ctx->internal_data.aes_internal.nr = AES128_NUM_ROUNDS; break;
//         case AES192_KEY_SIZE: ctx->internal_data.aes_internal.nr = AES192_NUM_ROUNDS; break;
//         case AES256_KEY_SIZE: ctx->internal_data.aes_internal.nr = AES256_NUM_ROUNDS; break;
//     }

//     return 0; /* success */
// }

// static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct) {
//     if (!ctx || !pt || !ct) return;
    
//     const u32* rk;
//     u32 s0, s1, s2, s3, t0, t1, t2, t3;
//     int r;

//     rk = ctx->internal_data.aes_internal.round_keys;
//     r = ctx->internal_data.aes_internal.nr;

//     /*
//      * map byte array block to cipher state
//      * and add initial round key:
//      */
//     s0 = GETU32(pt     ) ^ rk[0];
//     s1 = GETU32(pt +  4) ^ rk[1];
//     s2 = GETU32(pt +  8) ^ rk[2];
//     s3 = GETU32(pt + 12) ^ rk[3];

//     /* round 1: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
//     /* round 2: */
//     s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
//     s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
//     s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
//     s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
//     /* round 3: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
//     /* round 4: */
//     s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
//     s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
//     s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
//     s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
//     /* round 5: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
//     /* round 6: */
//     s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
//     s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
//     s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
//     s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
//     /* round 7: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
//     /* round 8: */
//     s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
//     s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
//     s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
//     s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
//     /* round 9: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
//     if (r > 10) {
//         /* round 10: */
//         s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
//         s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
//         s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
//         s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
//         /* round 11: */
//         t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
//         t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
//         t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
//         t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
//         if (r > 12) {
//             /* round 12: */
//             s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
//             s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
//             s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
//             s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
//             /* round 13: */
//             t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
//             t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
//             t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
//             t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
//         }
//     }
//     rk += r << 2;

//     /*
//      * apply last round and
//      * map cipher state to byte array block:
//      */
//     s0 =
//         (Te2[(t0 >> 24)       ] & 0xff000000) ^
//         (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
//         (Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
//         (Te1[(t3      ) & 0xff] & 0x000000ff) ^
//         rk[0];
//     PUTU32(ct     , s0);
//     s1 =
//         (Te2[(t1 >> 24)       ] & 0xff000000) ^
//         (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
//         (Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
//         (Te1[(t0      ) & 0xff] & 0x000000ff) ^
//         rk[1];
//     PUTU32(ct +  4, s1);
//     s2 =
//         (Te2[(t2 >> 24)       ] & 0xff000000) ^
//         (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
//         (Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
//         (Te1[(t1      ) & 0xff] & 0x000000ff) ^
//         rk[2];
//     PUTU32(ct +  8, s2);
//     s3 =
//         (Te2[(t3 >> 24)       ] & 0xff000000) ^
//         (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
//         (Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
//         (Te1[(t2      ) & 0xff] & 0x000000ff) ^
//         rk[3];
//     PUTU32(ct + 12, s3);
// }

// static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt) {
//     if (!ctx || !ct || !pt) return;
    
//     const u32 *rk;
//     u32 s0, s1, s2, s3, t0, t1, t2, t3;
//     int r;

//     rk = ctx->internal_data.aes_internal.round_keys;
//     r = ctx->internal_data.aes_internal.nr;

//     /*
//      * map byte array block to cipher state
//      * and add initial round key:
//      */
//     s0 = GETU32(pt     ) ^ rk[0];
//     s1 = GETU32(pt +  4) ^ rk[1];
//     s2 = GETU32(pt +  8) ^ rk[2];
//     s3 = GETU32(pt + 12) ^ rk[3];
//     /* round 1: */
//     t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[ 4];
//     t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[ 5];
//     t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[ 6];
//     t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[ 7];
//     /* round 2: */
//     s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[ 8];
//     s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[ 9];
//     s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[10];
//     s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[11];
//     /* round 3: */
//     t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[12];
//     t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[13];
//     t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[14];
//     t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[15];
//     /* round 4: */
//     s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[16];
//     s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[17];
//     s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[18];
//     s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[19];
//     /* round 5: */
//     t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[20];
//     t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[21];
//     t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[22];
//     t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[23];
//     /* round 6: */
//     s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[24];
//     s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[25];
//     s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[26];
//     s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[27];
//     /* round 7: */
//     t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[28];
//     t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[29];
//     t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[30];
//     t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[31];
//     /* round 8: */
//     s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[32];
//     s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[33];
//     s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[34];
//     s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[35];
//     /* round 9: */
//     t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[36];
//     t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[37];
//     t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[38];
//     t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[39];
//     if (r > 10) {
//         /* round 10: */
//         s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[40];
//         s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[41];
//         s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[42];
//         s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[43];
//         /* round 11: */
//         t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[44];
//         t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[45];
//         t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[46];
//         t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[47];
//         if (r > 12) {
//             /* round 12: */
//             s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[48];
//             s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[49];
//             s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[50];
//             s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[51];
//             /* round 13: */
//             t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[52];
//             t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[53];
//             t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[54];
//             t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[55];
//         }
//     }
//     rk += r << 2;

//     /*
//      * apply last round and
//      * map cipher state to byte array block:
//      */
//     s0 =
//         ((u32)Td4[(t0 >> 24)       ] << 24) ^
//         ((u32)Td4[(t3 >> 16) & 0xff] << 16) ^
//         ((u32)Td4[(t2 >>  8) & 0xff] <<  8) ^
//         ((u32)Td4[(t1      ) & 0xff])       ^
//         rk[0];
//     PUTU32(pt     , s0);
//     s1 =
//         ((u32)Td4[(t1 >> 24)       ] << 24) ^
//         ((u32)Td4[(t0 >> 16) & 0xff] << 16) ^
//         ((u32)Td4[(t3 >>  8) & 0xff] <<  8) ^
//         ((u32)Td4[(t2      ) & 0xff])       ^
//         rk[1];
//     PUTU32(pt +  4, s1);
//     s2 =
//         ((u32)Td4[(t2 >> 24)       ] << 24) ^
//         ((u32)Td4[(t1 >> 16) & 0xff] << 16) ^
//         ((u32)Td4[(t0 >>  8) & 0xff] <<  8) ^
//         ((u32)Td4[(t3      ) & 0xff])       ^
//         rk[2];
//     PUTU32(pt +  8, s2);
//     s3 =
//         ((u32)Td4[(t3 >> 24)       ] << 24) ^
//         ((u32)Td4[(t2 >> 16) & 0xff] << 16) ^
//         ((u32)Td4[(t1 >>  8) & 0xff] <<  8) ^
//         ((u32)Td4[(t0      ) & 0xff])       ^
//         rk[3];
//     PUTU32(pt + 12, s3);
// }












// static void aes_dispose(BlockCipherContext *ctx) {
//     if (!ctx) return;
//     // Clear the key material in aes_internal
//     memset(&ctx->internal_data.aes_internal, 0,
//     sizeof(ctx->internal_data.aes_internal));
// }










// static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct) {
//     if (!ctx || !pt || !ct) return;
//     AesInternal* st = &ctx->aes_internal;

//     /* Real code would do AES encryption. 
//     We'll do a trivial mock: XOR with 0xAA for demonstration. */
//     // for (size_t i = 0; i < st->block_size; i++) {
//     //     ct[i] = pt[i] ^ 0xAA;
//     // }

//     const u32* rk;
//     u32 s0, s1, s2, s3, t0, t1, t2, t3;
//     int r;

//     rk = st->round_keys; 
//     r = st->nr;

//     /*
//      * map byte array block to cipher state
//      * and add initial round key:
//      */
//     s0 = GETU32(pt     ) ^ rk[0];
//     s1 = GETU32(pt +  4) ^ rk[1];
//     s2 = GETU32(pt +  8) ^ rk[2];
//     s3 = GETU32(pt + 12) ^ rk[3];

//     /* round 1: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
//     /* round 2: */
//     s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
//     s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
//     s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
//     s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
//     /* round 3: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
//     /* round 4: */
//     s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
//     s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
//     s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
//     s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
//     /* round 5: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
//     /* round 6: */
//     s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
//     s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
//     s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
//     s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
//     /* round 7: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
//     /* round 8: */
//     s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
//     s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
//     s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
//     s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
//     /* round 9: */
//     t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
//     t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
//     t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
//     t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
//     if (r > 10) {
//         /* round 10: */
//         s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
//         s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
//         s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
//         s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
//         /* round 11: */
//         t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
//         t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
//         t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
//         t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
//         if (r > 12) {
//             /* round 12: */
//             s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
//             s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
//             s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
//             s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
//             /* round 13: */
//             t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
//             t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
//             t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
//             t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
//         }
//     }
//     rk += r << 2;

//     /*
//      * apply last round and
//      * map cipher state to byte array block:
//      */
//     s0 =
//         (Te2[(t0 >> 24)       ] & 0xff000000) ^
//         (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
//         (Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
//         (Te1[(t3      ) & 0xff] & 0x000000ff) ^
//         rk[0];
//     PUTU32(ct     , s0);
//     s1 =
//         (Te2[(t1 >> 24)       ] & 0xff000000) ^
//         (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
//         (Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
//         (Te1[(t0      ) & 0xff] & 0x000000ff) ^
//         rk[1];
//     PUTU32(ct +  4, s1);
//     s2 =
//         (Te2[(t2 >> 24)       ] & 0xff000000) ^
//         (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
//         (Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
//         (Te1[(t1      ) & 0xff] & 0x000000ff) ^
//         rk[2];
//     PUTU32(ct +  8, s2);
//     s3 =
//         (Te2[(t3 >> 24)       ] & 0xff000000) ^
//         (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
//         (Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
//         (Te1[(t2      ) & 0xff] & 0x000000ff) ^
//         rk[3];
//     PUTU32(ct + 12, s3);
// }

// static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt) {
//     if (!ctx || !ct || !pt) return;
//     AesInternal* st = &ctx->aes_internal;

//     /* trivial mock: XOR with 0xAA again. */
//     for (size_t i = 0; i < st->block_size; i++) {
//     pt[i] = ct[i] ^ 0xAA;
//     }
// }

// static void aes_dispose(BlockCipherContext *ctx) {
//     if (!ctx) return;
//     AesInternal* st = &ctx->aes_internal;
//     /* zero out everything */
//     memset(st, 0, sizeof(*st));
// }





















// #include "../../include/blockcipher/block_cipher_aes.h"
// #include <string.h>  // for memcpy, etc.

// /* Internally used structure to hold AES round keys, state, etc. */
// typedef struct AesInternal {
//     u8 round_keys[240]; // max for AES-256
//     int nr;                  // number of rounds
//     // ...
// } AesInternal;

// /* Forward declarations of static functions. */
// static int  aes_init(BlockCipherContext *ctx, const u8 *key, size_t key_len);
// static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct);
// static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt);
// static void aes_dispose(BlockCipherContext *ctx);

// /* The vtable for AES. */
// static const BlockCipherApi AES_API = {
//     .name          = "AES",
//     .block_size    = 16,
//     .key_size      = 16,  /* we might only do AES-128 for this example */
//     .init          = aes_init,
//     .encrypt_block = aes_encrypt,
//     .decrypt_block = aes_decrypt,
//     .dispose       = aes_dispose
// };

// const BlockCipherApi *get_aes_api(void)
// {
//     return &AES_API;
// }

// static int aes_init(BlockCipherContext *ctx, const u8 *key, size_t key_len)
// {
//     if (!ctx || !key) return -1;
//     if (key_len != 16) return -1; // For AES-128 example

//     /* Save pointer to the vtable, just in case it's not set yet. */
//     ctx->api = &AES_API;

//     /* The internal_data can be interpreted as our AesInternal. */
//     AesInternal *st = (AesInternal *) ctx->internal_data;
//     memset(st, 0, sizeof(*st));

//     // ... perform key expansion, fill st->round_keys, st->nr etc. ...
//     // For brevity, not shown here.

//     return 0; // success
// }

// static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct)
// {
//     // if (!ctx || !pt || !ct) return;
//     // AesInternal *st = (AesInternal *)ctx->internal_data;

//     // ... do block encryption using st->round_keys ...
// }

// static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt)
// {
//     // if (!ctx || !ct || !pt) return;
//     // AesInternal *st = (AesInternal *)ctx->internal_data;

//     // ... do block decryption ...
// }

// static void aes_dispose(BlockCipherContext *ctx)
// {
//     if (!ctx) return;
//     AesInternal *st = (AesInternal *)ctx->internal_data;
//     memset(st, 0, sizeof(*st)); // zeroize round keys
// }
