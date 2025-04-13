/* File: src/block_cipher/block_cipher_factory.c */
#include "../../include/block_cipher/block_cipher_api.h"
// #include "../../include/block_cipher/block_cipher_aes.h"

/* 
   If you had block_cipher_aria.h, block_cipher_lea.h, you'd include them too.
   e.g. #include "block_cipher_aria.h"
*/

// #include <string.h>

const BlockCipherApi* block_cipher_factory(const char *name) {
    if (!name) return NULL;

    if (strcmp(name, "AES") == 0) {
        return get_aes_api();
    }
    /* 
    else if (strcmp(name, "ARIA") == 0) return get_aria_api();
    else if (strcmp(name, "LEA") == 0)  return get_lea_api();
    */
    return NULL;
}

void print_cipher_internal(const BlockCipherContext* ctx, const char* cipher_type) {
    if (ctx == NULL) {
        printf("BlockCipherContext is NULL\n");
        return;
    }
    if (cipher_type == NULL) {
        printf("Cipher type is NULL\n");
        return;
    }

    printf("----------------------------------------------------------------------\n");
    printf("Cipher Type: %s\n", cipher_type);
    printf("----------------------------------------------------------------------\n");
    printf("| %-20s | %-20s | %-20s |\n", "Field", "Address", "Offset");
    printf("----------------------------------------------------------------------\n");

    printf("| %-20s | %-20p | %-20ld |\n", 
           "Block Size", 
           (void*)&ctx->internal_data.aes_internal.block_size, 
           (long)((unsigned char*)&ctx->internal_data.aes_internal.block_size - (unsigned char*)ctx));

    printf("| %-20s | %-20p | %-20ld |\n", 
           "Key Length", 
           (void*)&ctx->internal_data.aes_internal.key_len, 
           (long)((unsigned char*)&ctx->internal_data.aes_internal.key_len - (unsigned char*)ctx));

    printf("| %-20s | %-20p | %-20ld |\n", 
           "Round Keys", 
           (void*)&ctx->internal_data.aes_internal.round_keys, 
           (long)((unsigned char*)&ctx->internal_data.aes_internal.round_keys - (unsigned char*)ctx));

    printf("| %-20s | %-20p | %-20ld |\n", 
            "Number of Rounds", 
            (void*)&ctx->internal_data.aes_internal.nr, 
            (long)((unsigned char*)&ctx->internal_data.aes_internal.nr - (unsigned char*)ctx));

    printf("----------------------------------------------------------------------\n");
    printf("---------------------------------------------------------------------------------------------\n");
    printf("| %-20s | %-20s | %-20s | %-20s |\n", "Index", "Address", "Offset", "Value");
    printf("---------------------------------------------------------------------------------------------\n");
    for (long unsigned int i = 0; i < sizeof(ctx->internal_data.aes_internal.round_keys) / sizeof(ctx->internal_data.aes_internal.round_keys[0]); i++) {
        printf("| %-20ld | %-20p | %-20ld | %-20X |\n", 
               i, 
               (void*)&ctx->internal_data.aes_internal.round_keys[i], 
               (long)((unsigned char*)&ctx->internal_data.aes_internal.round_keys[i] - (unsigned char*)ctx), 
               ctx->internal_data.aes_internal.round_keys[i]);
        if ((i + 1) % 8 == 0) {
            printf("---------------------------------------------------------------------------------------------\n");
        }
    }
    // printf("\n");
    printf("---------------------------------------------------------------------------------------------\n");
}

// #include "../../include/blockcipher/block_cipher_aes.h"
// #include "block_cipher_aria.h"
// #include "block_cipher_lea.h"

// const BlockCipherApi *block_cipher_factory(const char *name)
// {
//     if (!name) return NULL;
//     if (strcmp(name, "AES") == 0)   return get_aes_api();
//     // if (strcmp(name, "ARIA") == 0)  return get_aria_api();
//     // if (strcmp(name, "LEA") == 0)   return get_lea_api();
//     return NULL; // unknown
// }
