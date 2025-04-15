/* File: src/main.c */
#include "../include/cryptomodule_api.h"
#include "cryptomodule_utils.h"
#include "../include/cryptomodule_test.h"
#include "../include/block_cipher/block_cipher_api.h"

/* Enable core dumps and set signal handlers for debugging */
#include <signal.h>
#include <stdlib.h>
#include <execinfo.h>
#include <unistd.h>

// #define TEST_FLAG 1

int main(void) {

    KAT_TEST_BLOCKCIPHER(BLOCK_CIPHER_AES128);
    // KAT_TEST_BLOCKCIPHER(BLOCK_CIPHER_AES192);

#ifdef TEST_FLAG
    /* 1) Create a context and call init */
    BlockCipherContext ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* 2) Get the AES vtable. */
    u8 key[16] = {0}; /* example all zero */
    stringToByteArray("ffffffffffc000000000000000000000", key);
    printf("Key       : ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", key[i]);
    }
    printf("\n");

    /* 3) Encrypt or Decrypt a single 16-byte block. */
    u8 plaintext[16] = { 0x00, };
    stringToByteArray("00000000000000000000000000000000", plaintext);
    u8 ciphertext[16] = { 0x00, };
    u8 decrypted[16]  = { 0x00, };

    memset(&ctx, 0, sizeof(ctx));
    ctx.api = block_cipher_factory("AES");
    ctx.api->init(&ctx, key, AES128_KEY_SIZE, AES_BLOCK_SIZE, BLOCK_CIPHER_ENCRYPTION);
    ctx.api->process_block(&ctx, plaintext, ciphertext, BLOCK_CIPHER_ENCRYPTION);
    // ctx.api->dispose(&ctx);
    ctx.api->init(&ctx, key, AES128_KEY_SIZE, AES_BLOCK_SIZE, BLOCK_CIPHER_DECRYPTION);
    ctx.api->process_block(&ctx, ciphertext, decrypted, BLOCK_CIPHER_DECRYPTION);
    ctx.api->dispose(&ctx);
   
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
        printf("%02X ", plaintext[i]);
    }
    printf("\nEncrypted : ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\nDecrypted : ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", decrypted[i]);
    }
    puts("");
#endif
    return 0;
}