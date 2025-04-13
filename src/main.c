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

int main(void) {
    /* 1) Create a context and call init */
    BlockCipherContext ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* 2) Get the AES vtable. */
    u8 key[16] = {0}; /* example all zero */
    stringToByteArray("2B7E151628AED2A6ABF7158809CF4F3C", key);
    printf("Key       : ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", key[i]);
    }
    printf("\n");

    /* 3) Encrypt or Decrypt a single 16-byte block. */
    u8 plaintext[16] = { 0x00, };
    stringToByteArray("6BC1BEE22E409F96E93D7E117393172A", plaintext);
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

    // KAT_TEST_BLOCKCIPHER_AES();

    // /* 1) Get the AES vtable. */
    // const BlockCipherApi *aes_api = get_aes_api();

    // /* 2) Create a context and call init. */
    // BlockCipherContext ctx;
    // memset(&ctx, 0, sizeof(ctx));

    // /* For AES-128, block_size=16, key_len=16. */
    // u8 key[16] = {0}; /* example all zero */
    // if (aes_api->init(&ctx, AES_BLOCK_SIZE, key, AES128_KEY_SIZE) != 0) {
    //     printf("Failed to init AES.\n");
    //     return 1;
    // }

    // /* 3) Encrypt or Decrypt a single 16-byte block. */

    // u8 plaintext[16] = {};
    // stringToByteArray("96AB5C2FF612D9DFAAE8C31F30C42168", plaintext);
    // u8 ciphertext[16] = {0};
    // u8 decrypted[16]  = {0};

    // aes_api->encrypt_block(&ctx, plaintext, ciphertext);
    // aes_api->decrypt_block(&ctx, ciphertext, decrypted);

    // printf("Original : ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", plaintext[i]);
    // }
    // printf("\nEncrypted: ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", ciphertext[i]);
    // }
    // puts("");
    // /* 4) Dispose. */
    // if (aes_api->dispose) {
    //     aes_api->dispose(&ctx);
    // }

    // printf("\nDecrypted: ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", decrypted[i]);
    // }

    // /* 1) Initialize entire cryptomodule. (optional) */
    // cryptomodule_status_t rc = cryptomodule_init();
    // if (rc != CRYPTOMODULE_OK) {
    //     printf("Failed to init cryptomodule\n");
    //     return 1;
    // }

    // /* 2) Acquire AES vtable. */
    // const BlockCipherApi *aes_api = get_aes_api();
    // if (!aes_api) {
    //     printf("No AES API available.\n");
    //     cryptomodule_cleanup();
    //     return 1;
    // }

    // /* 3) Prepare a cipher context. */
    // BlockCipherContext ctx;
    // // memset(&ctx, 0, sizeof(ctx));
    // clear_ctx(&ctx);

    // /* 16-byte key for AES-128 example. */
    // // 32-byte key for AES-256
    // uint8_t key[32] = {
    //     0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    //     0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
    //     0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
    //     0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
    //  };

    // /* 4) Initialize AES. */
    // if (aes_api->init(&ctx, 16, key, 32) != 0) {
    //     printf("AES init failed (maybe invalid block/key size)\n");
    //     return 1;
    // }

    // /* 5) Encrypt/Decrypt a block. */
    // uint8_t plaintext[16]  = "HelloAES_Example"; 
    // uint8_t ciphertext[16] = {0};
    // uint8_t decrypted[16]  = {0};

    // aes_api->encrypt_block(&ctx, plaintext, ciphertext);
    // aes_api->decrypt_block(&ctx, ciphertext, decrypted);

    // printf("Plaintext : %s\n", plaintext);

    // printf("Ciphertext: ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", ciphertext[i]);
    // }
    // printf("\n");

    // printf("Decrypted : %s\n", decrypted);

    // /* 6) Dispose AES context. */
    // if (aes_api->dispose) aes_api->dispose(&ctx);

    // /* 7) Cleanup cryptomodule. */
    // cryptomodule_cleanup();


    // AES_TEST
    // cryptomodule_status_t rc = cryptomodule_init();
    // if (rc != CRYPTOMODULE_OK) {
    //     printf("Failed to init cryptomodule\n");
    //     return 1;
    // }
    // const BlockCipherApi* aes_api = get_aes_api();
    // if (!aes_api) {
    //     printf("No AES API available.\n");
    //     cryptomodule_cleanup();
    //     return 1;
    // }
    // BlockCipherContext ctx;
    // clear_ctx(&ctx);

    // const char* inputString = "00000000000000000000000000000000";
    // u8 plaintext[16];
    // stringToByteArray(inputString, plaintext);
    // // for (int i = 0; i < 16; i++) {
    // //     printf("%02X ", plaintext[i]);
    // // } puts("");

    // const char* keyString = "ffffffffffffffffffffffffffffffff";
    // u8 key[16];
    // stringToByteArray(keyString, key);
    // // for (int i = 0; i < 16; i++) {
    // //     printf("%02X ", key[i]);
    // // } puts("");
    
    // u8 ciphertext[16];
    // u8 decrypted[16];

    // /* 4) Initialize AES. */
    // if (aes_api->init(&ctx, 16, key, 16) != 0) {
    //     printf("AES init failed (maybe invalid block/key size)\n");
    //     return 1;
    // }

    // /* 5) Encrypt/Decrypt a block. */

    // aes_api->encrypt_block(&ctx, plaintext, ciphertext);
    // // aes_api->decrypt_block(&ctx, ciphertext, decrypted);

    // printf("Plaintext: ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", plaintext[i]);
    // } puts("");
    
    // printf("Ciphertext: ");
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X ", ciphertext[i]);
    // }
    // printf("\n");

    // // printf("Decrypted : %s\n", decrypted);

    // /* 6) Dispose AES context. */
    // if (aes_api->dispose) aes_api->dispose(&ctx);

    // cryptomodule_cleanup();

    return 0;
}


// /* File: src/main.c */

// /* The single master include for the entire cryptomodule */
// #include "../include/aph.h"

// int main(void)
// {
//     /* 1) Initialize the entire cryptomodule. */
//     cryptomodule_status_t rc = cryptomodule_init();
//     if (rc != CRYPTOMODULE_OK) {
//         printf("Init error: %d\n", rc);
//         return 1;
//     }

    // /* 2) Grab an AES block cipher API. */
    // const BlockCipherApi *aes_api = get_aes_api();
    // if (!aes_api) {
    //     printf("AES API not available.\n");
    //     cryptomodule_cleanup();
    //     return 1;
    // }

//     // /* 3) Prepare a context. */
//     // BlockCipherContext ctx;
//     // memset(&ctx, 0, sizeof(ctx));

//     // /* Example key for AES-128. */
//     // uint8_t key[16] = {0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
//     //                    0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F};

//     // if (aes_api->init(&ctx, key, sizeof(key)) != 0) {
//     //     printf("AES init failed.\n");
//     //     cryptomodule_cleanup();
//     //     return 1;
//     // }

//     // /* 4) Encrypt/Decrypt a single block. */
//     // uint8_t plaintext[16]  = "Hello AES World";
//     // uint8_t ciphertext[16] = {0};
//     // uint8_t decrypted[16]  = {0};

//     // aes_api->encrypt_block(&ctx, plaintext, ciphertext);
//     // aes_api->decrypt_block(&ctx, ciphertext, decrypted);

//     // printf("Plaintext : %s\n", plaintext);
//     // printf("Ciphertext: ");
//     // for (int i = 0; i < 16; i++) {
//     //     printf("%02X ", ciphertext[i]);
//     // }
//     // printf("\nDecrypted : %s\n", decrypted);

//     // /* 5) Dispose the cipher's internal data. */
//     // if (aes_api->dispose) {
//     //     aes_api->dispose(&ctx);
//     // }

//     // /* 6) Optionally, call other categories (Hash, MAC, etc.) here. */

//     // /* 7) Finally, cleanup the cryptomodule. */
//     // rc = cryptomodule_cleanup();
//     // if (rc != CRYPTOMODULE_OK) {
//     //     printf("Cleanup error: %d\n", rc);
//     //     /* handle error or ignore */
//     // }

//     return 0;
// }


// #include <stdio.h>
// #include <include/cryptomodule/aph.h> // Everything is included

// int main(void) {
//     // Example usage: AES test
//     cryptomodule_status_t ret = cryptomodule_init();
//     if (ret != CRYPTOMODULE_OK) { 
//         printf("Init error!\n"); 
//         return 1;
//     }

//     // Call your AES or GCM or other routines
//     // ...
//     cryptomodule_cleanup();
//     return 0;
// }

// #include <stdio.h>
// #include <string.h>
// #include <stdint.h>

// #include <include/blockcipher/block_cipher.h>
// #include <include/blockcipher/block_cipher_aes.h>
// // or #include <cryptomodule/block/block_cipher_factory.h>

// int main(void)
// {
//     // Suppose we directly pick AES. If you want dynamic picking, use factory.
//     const BlockCipherApi *api = get_aes_api();

//     // Prepare context
//     BlockCipherContext ctx;
//     memset(&ctx, 0, sizeof(ctx));

//     // 16-byte key for AES-128
//     uint8_t key[16] = {0x00, 0x01, 0x02, 0x03,
//                        0x04, 0x05, 0x06, 0x07,
//                        0x08, 0x09, 0x0A, 0x0B,
//                        0x0C, 0x0D, 0x0E, 0x0F};

//     // Initialize
//     if (api->init(&ctx, key, sizeof(key)) != 0) {
//         printf("Failed to init block cipher.\n");
//         return 1;
//     }

//     // Example block of plaintext
//     uint8_t plaintext[16]  = "Hello  AES test"; // 16 bytes
//     uint8_t ciphertext[16] = {0};
//     uint8_t decrypted[16]  = {0};

//     // Encrypt the block
//     api->encrypt_block(&ctx, plaintext, ciphertext);

//     // Decrypt
//     api->decrypt_block(&ctx, ciphertext, decrypted);

//     printf("Original : %s\n", plaintext);
//     printf("Encrypted: ");
//     for (int i = 0; i < 16; i++) {
//         printf("%02X ", ciphertext[i]);
//     }
//     printf("\nDecrypted: %s\n", decrypted);

//     // Dispose
//     if (api->dispose) {
//         api->dispose(&ctx);
//     }

//     return 0;
// }
