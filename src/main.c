/* File: src/main.c */
#include "../include/api_cryptomodule.h"

/* Enable core dumps and set signal handlers for debugging */
#include <signal.h>
#include <stdlib.h>
#include <execinfo.h>
#include <unistd.h>

// #define BLOCK_CIPHER_TEST_FLAG 1
#define MODE_OF_OPERATION_TEST_FLAG 1
// #define PADDING_TEST_FLAG 1

int main(void) {

    // KAT_TEST_BLOCKCIPHER(BLOCK_CIPHER_AES128);
    // KAT_TEST_BLOCKCIPHER(BLOCK_CIPHER_AES192);
    // KAT_TEST_BLOCKCIPHER(BLOCK_CIPHER_AES256);

#ifdef MODE_OF_OPERATION_TEST_FLAG
   // 1) Prepare key and IV
   uint8_t key[16] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
    };
    uint8_t iv[16] = { 0 };     // for CBC/CTR/GCM

    printf("                    Key (%u): ", 16);
    for (size_t i = 0; i < sizeof(key)/sizeof(u8); i++) {
        printf("(%ld)%02X:", i, key[i]);
    } puts("");

    // 2) Example plaintext > 1 block (48 bytes = 3 AES blocks)
    // const char *plaintext = 
    //     "The quick brown fox jumps over the lazy dog!!!";
    // size_t pt_len = strlen(plaintext);  // 43 bytes

    size_t pt_len = 16;
    size_t pt_max_len = 32;

    u8 *mode_pt = (u8*)malloc(pt_max_len);
    if (!mode_pt) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    for (size_t i = 0; i < pt_len; i++) {
        mode_pt[i] = (uint8_t)i*i;
    }

    printf("[Fit-] Original message (%2zu): ", pt_len);
    for (size_t i = 0; i < pt_len; i++) {
        printf("(%ld)%02X:", i, mode_pt[i]);
    } puts("");

    printf("[Real] Original message (%2zu): ", pt_max_len);
    for (size_t i = 0; i < pt_max_len; i++) {
        printf("(%ld)%02X:", i, mode_pt[i]);
    } puts("");

    // For ECB/CBC with padding, ciphertext_len may grow by +block_size
    uint8_t mode_ct[64] = {0};
    size_t mode_ct_len = pt_max_len;

    // 3) Set up BlockCipherContext for AES


    // 4) Choose a mode: ECB or CBC (both defined in mode_api.h)
    ModeOfOperationContext mode_ctx;
    // BlockCipherContext cipher_ctx;
    mode_ctx.mode_api = mode_factory("ECB");

    mode_ctx.mode_api->mode_init(
        &mode_ctx, BLOCK_CIPHER_AES128, key, sizeof(key)/sizeof(u8), NULL, 0, mode_pt, pt_len, BLOCK_CIPHER_ENCRYPTION);
    // printf("Total length: %zu\n", mode_ctx.total_len);

    // size_t total_block_size = pkcs7_pad(pt, msg_len, BLOCK_SIZE);

    // printf("            Key: ");
    // for (size_t i = 0; i < sizeof(key)/sizeof(u8); i++) {
    //     printf("%02X ", key[i]);
    // }
    // puts("");
    // printf("            IV: ");
    // for (size_t i = 0; i < sizeof(iv)/sizeof(u8); i++) {
    //     printf("%02X ", iv[i]);
    // }
    // puts("");
    printf("      Padded Plaintext: (%2zu): ", mode_ctx.total_len);
    for (size_t i = 0; i < mode_ctx.total_len; i++) {
        printf("(%ld)%02X:", i, mode_pt[i]);
    } puts("");

    mode_ctx.mode_api->mode_update(
        &mode_ctx, mode_pt, mode_ct, mode_ctx.total_len, BLOCK_CIPHER_ENCRYPTION);
    
    printf("   (Update) Ciphertext: (%2zu): ", mode_ctx.total_len);
    for (size_t i = 0; i < mode_ctx.total_len; i++) {
        printf("(%ld)%02X:", i, mode_ct[i]);
    } puts("");


    // mode_ctx.api->mode_update(&mode_ctx, pt, ciphertext, pt_max_len, ciphertext_len, BLOCK_CIPHER_ENCRYPTION);
    // mode_ctx.api->mode_dispose(&mode_ctx);
    // cipher_ctx.cipher_api->cipher_dispose(&cipher_ctx);
    // printf("            Ciphertext: (%2zu): ", ciphertext_len);
    // for (size_t i = 0; i < ciphertext_len; i++) {
    //     printf("%02X ", ciphertext[i]);
    // }
    // puts("");

    free(mode_pt);

#endif

#ifdef PADDING_TEST_FLAG
    uint8_t buf[128];
    const char *msg = "HELLO WORLD";
    size_t msg_len = strlen(msg);
    memcpy(buf, msg, msg_len);

    // size_t msg_len = 16;
    // for (size_t i = 0; i < msg_len; i++) {
    //     buf[i] = (uint8_t)i;
    // }

    printf("Original message (%zu): ", msg_len);
    for (size_t i = 0; i < msg_len; i++) {
        printf("(%ld)%02X:", i, buf[i]);
    } puts("");

    // PKCS#7
    printf("\n----------------------------------- PKCS#7 -----------------------------------\n");
    size_t tot = pkcs7_pad(buf, msg_len, BLOCK_SIZE);
    printf("Padded message   (%zu): ", tot);
    for (size_t i = 0; i < tot; i++) {
        printf("(%ld)%02X:", i, buf[i]);
    } puts("");
    size_t unp = pkcs7_unpad(buf, tot, BLOCK_SIZE);
    printf("Unpadded message (%zu): ", unp);
    for (size_t i = 0; i < unp; i++) {
        printf("(%ld)%02X:", i, buf[i]);
    } puts("");

    // ANSI 9.23
    printf("\n----------------------------------- ANSI 9.23 -----------------------------------\n");
    // memcpy(buf, msg, msg_len);
    tot = ansi923_pad(buf, msg_len, BLOCK_SIZE);
    printf("Padded message   (%zu): ", tot);
    for (size_t i = 0; i < tot; i++) {
        printf("(%ld)%02X:", i, buf[i]);
    } puts("");
    unp = ansi923_unpad(buf, tot, BLOCK_SIZE);
    printf("Unpadded message (%zu): ", unp);
    for (size_t i = 0; i < unp; i++) {
        printf("(%ld)%02X:", i, buf[i]);
    } puts("");

    // ISO/IEC 7816-4
    printf("\n----------------------------------- ISO/IEC 7816-4 -----------------------------------\n");
    // memcpy(buf, msg, msg_len);
    tot = iso7816_4_pad(buf, msg_len, BLOCK_SIZE);
    printf("Padded message   (%zu): ", tot);
    for (size_t i = 0; i < tot; i++) {
        printf("(%ld)%02X:", i, buf[i]);
    } puts("");
    unp = iso7816_4_unpad(buf, tot, BLOCK_SIZE);
    printf("Unpadded message (%zu): ", unp);
    for (size_t i = 0; i < unp; i++) {
        printf("(%ld)%02X:", i, buf[i]);
    } puts("");
#endif

#ifdef BLOCK_CIPHER_TEST_FLAG
    /* 1) Create a context and call init */
    BlockCipherContext cipher_ctx;
    memset(&cipher_ctx, 0, sizeof(cipher_ctx));

    #define key_len AES128_KEY_SIZE

    /* 2) Get the AES vtable. */
    // u8 key[key_len] = {0}; /* example all zero */
    // stringToByteArray("f8000000000000000000000000000000", key);
    printf("Key       : ");
    for (int i = 0; i < key_len; i++) {
        printf("%02X ", key[i]);
    }
    printf("\n");

    /* 3) Encrypt or Decrypt a single 16-byte block. */
    u8 pt[16] = { 0x00, };
    // stringToByteArray("00000000000000000000000000000000", pt);
    for (size_t i = 0; i < sizeof(pt)/sizeof(u8); i++) {
        pt[i] = (u8)i*i;
    }
    u8 ct[16] = { 0x00, };
    u8 dt[16]  = { 0x00, };

    memset(&cipher_ctx, 0, sizeof(cipher_ctx));
    cipher_ctx.cipher_api = block_cipher_factory("AES");
    cipher_ctx.cipher_api->cipher_init(&cipher_ctx, key, key_len, AES_BLOCK_SIZE, BLOCK_CIPHER_ENCRYPTION);
    cipher_ctx.cipher_api->cipher_process(&cipher_ctx, pt, ct, BLOCK_CIPHER_ENCRYPTION);
    // ctx.api->dispose(&ctx);
    cipher_ctx.cipher_api->cipher_init(&cipher_ctx, key, key_len, AES_BLOCK_SIZE, BLOCK_CIPHER_DECRYPTION);
    cipher_ctx.cipher_api->cipher_process(&cipher_ctx, ct, dt, BLOCK_CIPHER_DECRYPTION);
    cipher_ctx.cipher_api->cipher_dispose(&cipher_ctx);
   
    // -- ENCRYPTION -- 
    // memset(&enc_ctx, 0, sizeof(enc_ctx));
    // enc_ctx.api = block_cipher_factory("AES");
    // enc_ctx.api->init(&enc_ctx, key, AES128_KEY_SIZE, AES_BLOCK_SIZE, BLOCK_CIPHER_ENCRYPTION);
    // enc_ctx.api->process_block(&enc_ctx, plaintext, ciphertext, BLOCK_CIPHER_ENCRYPTION);
    // enc_ctx.api->dispose(&enc_ctx);

    // -- DECRYPTION --
    // memset(&dec_ctx, 0, sizeof(dec_ctx));
    // dec_ctx.api = block_cipher_factory("AES");
    // dec_ctx.api->init(&dec_ctx, key, 16, 16, BLOCK_CIPHER_DECRYPTION);
    // dec_ctx.api->process_block(&dec_ctx, ciphertext, decrypted, BLOCK_CIPHER_DECRYPTION);
    // dec_ctx.api->dispose(&dec_ctx);
    
    printf("Original  : ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", pt[i]);
    }
    printf("\nEncrypted : ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", ct[i]);
    }
    printf("\nDecrypted : ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", dt[i]);
    }
    puts("");
#endif
    return 0;
}