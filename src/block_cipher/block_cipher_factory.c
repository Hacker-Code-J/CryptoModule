/* File: src/block_cipher/block_cipher_factory.c */
#include "../../include/block_cipher/block_cipher_api.h"
#include "../../include/block_cipher/block_cipher_aes.h"

/* 
   If you had block_cipher_aria.h, block_cipher_lea.h, you'd include them too.
   e.g. #include "block_cipher_aria.h"
*/

#include <string.h>

const BlockCipherApi* block_cipher_factory(const char *name)
{
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

void print_cipher_internal(const BlockCipherContext* ctx, const char* cipher_type)
{
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
    printf("Block Size: %zu\n", ctx->internal_data.aes_internal.block_size);
    printf("Key Length: %zu\n", ctx->internal_data.aes_internal.key_len);
    printf("Number of Rounds: %d\n", ctx->internal_data.aes_internal.nr);
    // Add more fields as needed
    printf("Round Keys: \n");
    for (int i = 0; i < 60; i++) {
        printf("%08X ", ctx->internal_data.aes_internal.round_keys[i]);
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\n");
    printf("----------------------------------------------------------------------\n");
    // Add more fields as needed
    // printf("Internal Data: %p\n", ctx->internal_data);
    // printf("Internal Data Size: %zu\n", sizeof(ctx->internal_data));
    // printf("Internal Data Address: %p\n", (void*)&ctx->internal_data);

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
