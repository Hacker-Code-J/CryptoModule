/* File: src/mode/mode_factory.c */

#include "../../include/mode/api_mode.h"

const ModeOfOperationApi *mode_factory(const char *name) {
    if (!name) return NULL;

    if (strcmp(name, "GCM") == 0) {
        return get_gcm_api();
    }
    else if (strcmp(name, "CBC") == 0) {
        return get_cbc_api();
    }
    else if (strcmp(name, "CTR") == 0) {
        return get_ctr_api();
    } else {
       fprintf(stderr, "Invalid cipher type for mode: %s\n", name);
        return NULL;
    }
    // Add more modes as needed
    return NULL;
}

void print_mode_internal(const ModeOfOperationContext* mode_ctx, const char* mode_type) {
    if (mode_ctx == NULL) {
        printf("ModeOfOperationContext is NULL\n");
        return;
    }
    if (mode_type == NULL) {
        printf("Mode type is NULL\n");
        return;
    }

    printf("----------------------------------------------------------------------\n");
    printf("Mode Type: %s\n", mode_type);
    printf("----------------------------------------------------------------------\n");
    printf("| %-20s | %-20s | %-20s |\n", "Field", "Address", "Offset");
    printf("----------------------------------------------------------------------\n");

    // Print the fields of the ModeOfOperationContext
    printf("| %-20s | %-20p | %-20ld |\n", 
           "Mode Type", 
           (void*)&mode_ctx->mode_type, 
           (long)((unsigned char*)&mode_ctx->mode_type - (unsigned char*)mode_ctx));

    printf("| %-20s | %-20p | %-20ld |\n", 
           "Cipher Type", 
           (void*)&mode_ctx->cipher_type, 
           (long)((unsigned char*)&mode_ctx->cipher_type - (unsigned char*)mode_ctx));

    printf("| %-20s | %-20p | %-20ld |\n", 
           "Cipher Context", 
           (void*)&mode_ctx->cipher_ctx, 
           (long)((unsigned char*)&mode_ctx->cipher_ctx - (unsigned char*)mode_ctx));

    printf("| %-20s | %-20p | %-20ld |\n", 
           "Mode API", 
           (void*)&mode_ctx->mode_api, 
           (long)((unsigned char*)&mode_ctx->mode_api - (unsigned char*)mode_ctx));

    printf("----------------------------------------------------------------------\n");
    // Print the fields of the ModeInternal structure
    printf("| %-20s | %-20p | %-20ld |\n", 
           "IV", 
           (void*)&mode_ctx->mode_state.cbc_internal.iv, 
           (long)((unsigned char*)&mode_ctx->mode_state.cbc_internal.iv - (unsigned char*)mode_ctx));
    printf("| %-20s | %-20p | %-20ld |\n",
           "Counter", 
           (void*)&mode_ctx->mode_state.ctr_internal.counter, 
           (long)((unsigned char*)&mode_ctx->mode_state.ctr_internal.counter - (unsigned char*)mode_ctx));
    printf("| %-20s | %-20p | %-20ld |\n",
           "GHASH Table", 
           (void*)&mode_ctx->mode_state.gcm_internal.ghash_table, 
           (long)((unsigned char*)&mode_ctx->mode_state.gcm_internal.ghash_table - (unsigned char*)mode_ctx));
    printf("| %-20s | %-20p | %-20ld |\n",
           "GHASH H", 
           (void*)&mode_ctx->mode_state.gcm_internal.H, 
           (long)((unsigned char*)&mode_ctx->mode_state.gcm_internal.H - (unsigned char*)mode_ctx));
    printf("----------------------------------------------------------------------\n");
    printf("---------------------------------------------------------------------------------------------\n");
//     printf("| %-20s | %-20s | %-20s | %-20s |\n", "Index", "Address", "Offset", "Value");
//     printf("---------------------------------------------------------------------------------------------\n");
//     for (long unsigned int i = 0; i < sizeof(mode_ctx->mode_state.gcm_internal.ghash_table) / sizeof(mode_ctx->mode_state.gcm_internal.ghash_table[0]); i++) {
//         printf("| %-20ld | %-20p | %-20ld | %-20X |\n", 
//                i, 
//                (void*)&mode_ctx->mode_state.gcm_internal.ghash_table[i], 
//                (long)((unsigned char*)&mode_ctx->mode_state.gcm_internal.ghash_table[i] - (unsigned char*)mode_ctx), 
//                mode_ctx->mode_state.gcm_internal.ghash_table[i]);
//         if ((i + 1) % 8 == 0) {
//             printf("---------------------------------------------------------------------------------------------\n");
//         }
//     }
//     printf("---------------------------------------------------------------------------------------------\n");
    printf("\n");
}