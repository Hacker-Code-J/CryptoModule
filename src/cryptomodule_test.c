/* File: src/kat_verifier.c */

#include "../include/cryptomodule_test.h"
#include "../include/cryptomodule_utils.h"
#include "../include/block_cipher/block_cipher_api.h"
#include "../include/block_cipher/block_cipher_aes.h"
#include "../include/ansi_code.h"

void progress_bar(int current, int total) {
    int width = 50; // Width of the progress bar
    float progress = (float)current / total;
    int pos = width * progress;

    printf("\r[");
    for (int i = 0; i < width; ++i) {
        if (i < pos) printf("%s=", ANSI_FG_GREEN); // White for completed part
        else if (i == pos) printf("%s>", ANSI_FG_YELLOW); // Yellow for current position
        else printf("%s ", ANSI_FG_RED); // Red for remaining part
    }
    printf("%s] %d%% (%d/%d)", ANSI_RESET, (int)(progress * 100.0), current, total);    
}

void parse_hexline(u32 *dst, const char* src, size_t length) {
    for (size_t i = 0; i < length; i++) {
        u32 value = 0;
        if (sscanf(src + i * 8, "%08X", &value) != 1) {
            dst[i] = 0; // Default value if parsing fails
            // fprintf(stderr, "Error parsing hex string: %s\n", src + i * 8);
            // break;
        } else {
            dst[i] = value;
        }
    }
}

size_t byte_length(const char *string) {
    size_t string_length = strlen(string);
    size_t byte_length = string_length / 2; // 0x00 = 1 byte
    // if (string_length % 2 != 0) {
    //     fprintf(stderr, "Error: Invalid byte length in string: %s\n", string);
    //     return 0;
    // }
    return byte_length;
}

size_t word_length(const char *string) {
    size_t string_length = strlen(string);
    size_t word_length = string_length / 8; // 0x00 = 1 word
    // if (string_length % 8 != 0) {
    //     fprintf(stderr, "Error: Invalid word length in string: %s\n", string);
    //     return 0;
    // }
    return word_length;
}

void write_data(FILE *fp, const u32 *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        fprintf(fp, "%08x", data[i]);
    }
    fprintf(fp, "\n");
}

void create_BlockCipher_KAT_ReqFile(BlockCipherType type, const char *filename_fax, const char *filename_req) {
    FILE *fp_fax, *fp_req;
    char *line;
    size_t bufsize = MAX_LINE_LENGTH;
    int flag = 0;

    printf("\x1b[34m[REQ] ? Creating request file : %s\x1b[0m\n", filename_req);
    fp_fax = fopen(filename_fax, "r");
    if (fp_fax == NULL) {
        fprintf(stderr, "[REQ] Error opening file: %s\n", filename_fax);
        return;
    }

    fp_req = fopen(filename_req, "w");
    if (fp_req == NULL) {
        fprintf(stderr, "[REQ] Error opening file: %s\n", filename_req);
        fclose(fp_fax);
        return;
    }

    line = (char*)calloc(bufsize, sizeof(char));
    if (line == NULL) {
        fprintf(stderr, "[REQ] Memory allocation error\n");
        fclose(fp_fax);
        fclose(fp_req);
        return;
    }

    while (fgets(line, bufsize, fp_fax) != NULL) {
        // printf("[RSP] %s", line);
        if (strncmp(line, "[ENCRYPT]", 9) == 0) {
            fputs(line, fp_req); fputs("\n", fp_req);
        } else if (strncmp(line, "[DECRYPT]", 9) == 0) {
            flag = 1;
            fputs(line, fp_req); fputs("\n", fp_req);
        } else if (strncmp(line, "COUNT =", 7) == 0) {
            fputs(line, fp_req);
        } else if (strncmp(line, "KEY =", 5) == 0) {
            fputs(line, fp_req);
        } else if (flag == 0 && strncmp(line, "PT =", 4) == 0) {
            fputs(line, fp_req); fputs("\n", fp_req);
        } else if (flag == 1 && strncmp(line, "CT =", 4) == 0) {
            fputs(line, fp_req); fputs("\n", fp_req);
        } 
    } // while

    free(line);
    fclose(fp_fax);
    fclose(fp_req);
    printf("\x1b[36m[REQ] ! Created request file  : %s\x1b[0m\n", filename_req);
}

void create_BlockCipher_KAT_RspFile(BlockCipherType type, const char *filename_req, const char *filename_rsp) {
    FILE *fp_req, *fp_rsp;
    char *line;
    size_t bufsize = MAX_TXT_SIZE;
    int is_first_key = 1;
    int flag = 0;

    // Read the request file and create the response file
    printf("\x1b[34m[RSP] ? Creating response file: %s\x1b[0m\n", filename_rsp);
    fp_req = fopen(filename_req, "r");
    if (fp_req == NULL) {
        fprintf(stderr, "[RSP] Error opening file: %s\n", filename_req);
        return;
    }
    // Open the response file for writing
    fp_rsp = fopen(filename_rsp, "w");
    if (fp_rsp == NULL) {
        fprintf(stderr, "[RSP] Error opening file: %s\n", filename_rsp);
        fclose(fp_req);
        return;
    }

    // Allocate initial buffer for line
    line = (char*)calloc(bufsize, sizeof(char));
    if (line == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        fclose(fp_req);
        fclose(fp_rsp);
        return;
    }

    BlockCipherContext ctx;
    clear_block_cipher_ctx(&ctx);

    char cipher_name[5];
    sscanf(block_cipher_type_to_string(type), "%[^-]", cipher_name);
    // printf("[RSP] Cipher name: %s\n", cipher_name);
    ctx.api = block_cipher_factory(cipher_name);
    if (ctx.api == NULL) {
        fprintf(stderr, "[RSP] No AES API available.\n");
        free(line);
        fclose(fp_req);
        fclose(fp_rsp);
        return;
    }

    int key_size = 0;
    switch (type) {
        case BLOCK_CIPHER_AES128:
            key_size = AES128_KEY_SIZE;
            break;
        case BLOCK_CIPHER_AES192:
            key_size = AES192_KEY_SIZE;
            break;
        case BLOCK_CIPHER_AES256:
            key_size = AES256_KEY_SIZE;
            break;
        default:
            key_size = AES128_KEY_SIZE;
            break;
    }

    u32 *key_u32 = (u32 *)calloc(key_size / 4, sizeof(u32));
    if (key_u32 == NULL) {
        fprintf(stderr, "[RSP] Memory allocation error for key_u32\n");
        exit(EXIT_FAILURE);
    }
    u32 iv_u32[AES_BLOCK_SIZE / 4] = { 0, };
    u32 data_u32[AES_BLOCK_SIZE / 4] = { 0, };

    u8 *key = (u8*)calloc(key_size, sizeof(u8));
    if (key == NULL) {
        fprintf(stderr, "[RSP] Memory allocation error for key_u8\n");
        free(key_u32);
        exit(EXIT_FAILURE);
    }
    u8 iv[AES_BLOCK_SIZE] = { 0, };
    u8 data[AES_BLOCK_SIZE] = { 0, };
    u8 processed_data[AES_BLOCK_SIZE] = { 0, };
    
    size_t key_len_u32 = 0, iv_len_u32 = 0, pt_len_u32 = 0, ct_len_u32 = 0;

    while (fgets(line, bufsize, fp_req)) {
        // printf("[RSP] %s", line);
        if (strncmp(line, "[ENCRYPT]", 9) == 0) { 
            fputs(line, fp_rsp); fputs("\n", fp_rsp); 
        }
        if (strncmp(line, "[DECRYPT]", 9) == 0) {
            flag = 1; fputs("\n", fp_rsp); fputs(line, fp_rsp);
        }

        if (strncmp(line, "COUNT =", 7) == 0) {
            if (!is_first_key) { fputc('\n', fp_rsp); } 
            is_first_key = 0;
            fprintf(fp_rsp, "%s", line);
        } else if (strncmp(line, "KEY =", 5) == 0) {
            if (ctx.api->dispose) { ctx.api->dispose(&ctx); }
            key_len_u32 = word_length(line + 6);
            parse_hexline(key_u32, line + 6, key_len_u32);
            fputs(line, fp_rsp);
        } else if (flag == 0 && strncmp(line, "PT =", 4) == 0) {
            memset(data_u32, 0, sizeof(data_u32));
            pt_len_u32 = word_length(line + 5);
            parse_hexline(data_u32, line + 5, pt_len_u32);
            fputs(line, fp_rsp);
 
            memset(key, 0, sizeof(key));
            /* key_u32 (word) -> key (byte) */
            for (size_t i = 0; i < key_len_u32; i++) {
                key[4 * i    ] = (key_u32[i] >> 24) & 0xFF;
                key[4 * i + 1] = (key_u32[i] >> 16) & 0xFF;
                key[4 * i + 2] = (key_u32[i] >>  8) & 0xFF;
                key[4 * i + 3] = (key_u32[i]      ) & 0xFF;
            }
            
            memset(data, 0, sizeof(data)); word2byte(data_u32, data);
            fprintf(fp_rsp, "CT = ");
            // Initialize AES context
            ctx.api->init(&ctx, key, key_len_u32 * sizeof(u32), pt_len_u32 * sizeof(u32), BLOCK_CIPHER_ENCRYPTION);
            memset(key, 0, sizeof(key));

            // Encrypt the plaintext
            memset(processed_data, 0, sizeof(processed_data));
            ctx.api->process_block(&ctx, data, processed_data, BLOCK_CIPHER_ENCRYPTION);
            for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
                fprintf(fp_rsp, "%02x", processed_data[i]);
            }
            fprintf(fp_rsp, "\n");
            if (ctx.api->dispose) { ctx.api->dispose(&ctx); }
        } else if (flag == 1 && strncmp(line, "CT =", 4) == 0) {
            ct_len_u32 = word_length(line + 5);
            memset(data_u32, 0, sizeof(data_u32));
            parse_hexline(data_u32, line + 5, ct_len_u32);
            fputs(line, fp_rsp);

            memset(key, 0, sizeof(key));
            /* key_u32 (word) -> key (byte) */
            for (size_t i = 0; i < key_len_u32; i++) {
                key[4 * i    ] = (key_u32[i] >> 24) & 0xFF;
                key[4 * i + 1] = (key_u32[i] >> 16) & 0xFF;
                key[4 * i + 2] = (key_u32[i] >>  8) & 0xFF;
                key[4 * i + 3] = (key_u32[i]      ) & 0xFF;
            }

            memset(data, 0, sizeof(data)); word2byte(data_u32, data);
            fprintf(fp_rsp, "PT = ");
            // Initialize AES context
            ctx.api->init(&ctx, key, key_len_u32 * sizeof(u32), ct_len_u32 * sizeof(u32), BLOCK_CIPHER_DECRYPTION);
            memset(key, 0, sizeof(key));

            // Decrypt the ciphertext
            memset(processed_data, 0, sizeof(processed_data));
            ctx.api->process_block(&ctx, data, processed_data, BLOCK_CIPHER_DECRYPTION);
            for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
                fprintf(fp_rsp, "%02x", processed_data[i]);
            }
            fprintf(fp_rsp, "\n");
            if (ctx.api->dispose) { ctx.api->dispose(&ctx); }
        } 
    }

    free(key_u32);
    free(key);
    free(line);
    fclose(fp_req);
    fclose(fp_rsp);
    printf("\x1b[36m[RSP] ! Created response file : %s\x1b[0m\n", filename_rsp);
}

void KAT_TEST_BLOCKCIPHER(BlockCipherType type) {
    const char* file_path;
    if (type == BLOCK_CIPHER_AES128 || type == BLOCK_CIPHER_AES192 || type == BLOCK_CIPHER_AES256) {
        file_path = "./testvectors/block_cipher_tv/nist_aes/";
    } else if (type == BLOCK_CIPHER_ARIA128 || type == BLOCK_CIPHER_ARIA192 || type == BLOCK_CIPHER_ARIA256) {
        file_path = "./testvectors/block_cipher_tv/kisa_aria/";
    } else if (type == BLOCK_CIPHER_LEA128 || type == BLOCK_CIPHER_LEA192 || type == BLOCK_CIPHER_LEA256) {
        file_path = "./testvectors/block_cipher_tv/kisa_lea/";
    } else {
        fprintf(stderr, "[VERIFY] Unknown BlockCipherType: %d\n", type);
        return;
    }

    char filename_fax[100];
    char filename_req[100];
    char filename_rsp[100];
    
    if (type == BLOCK_CIPHER_AES128) {
        snprintf(filename_fax, sizeof(filename_fax), "%s%s", file_path, "ECB_AES128.fax");
        snprintf(filename_req, sizeof(filename_req), "%s%s", file_path, "ECB_AES128.req");
        snprintf(filename_rsp, sizeof(filename_rsp), "%s%s", file_path, "ECB_AES128.rsp");
    } else if (type == BLOCK_CIPHER_AES192) {
        snprintf(filename_fax, sizeof(filename_fax), "%s%s", file_path, "ECB_AES192.fax");
        snprintf(filename_req, sizeof(filename_req), "%s%s", file_path, "ECB_AES192.req");
        snprintf(filename_rsp, sizeof(filename_rsp), "%s%s", file_path, "ECB_AES192.rsp");
    } else if (type == BLOCK_CIPHER_AES256) {
        snprintf(filename_fax, sizeof(filename_fax), "%s%s", file_path, "ECB_AES256.fax");
        snprintf(filename_req, sizeof(filename_req), "%s%s", file_path, "ECB_AES256.req");
        snprintf(filename_rsp, sizeof(filename_rsp), "%s%s", file_path, "ECB_AES256.rsp");
    } else {
        fprintf(stderr, "[VERIFY] Unknown BlockCipherType: %d\n", type);
        return;
    }

    printf("%s%s--------------------------------- KAT TEST for %s ---------------------------------%s%s\n", 
        ANSI_BG_MAGENTA, ANSI_BOLD,
        block_cipher_type_to_string(type),
        ANSI_BG_DEFAULT, ANSI_RESET);
    
    create_BlockCipher_KAT_ReqFile(type, filename_fax, filename_req);
    create_BlockCipher_KAT_RspFile(type, filename_req, filename_rsp);

    printf("\n%s[PATH] Test vector file : %s\n", ANSI_FG_BMAGENTA, filename_fax);
    printf("[PATH] Request file     : %s\n", filename_req);
    printf("[PATH] Response file    : %s%s\n", filename_rsp, ANSI_RESET);

    FILE* fp_fax = fopen(filename_fax, "r");
    if (fp_fax == NULL) {
        fprintf(stderr, "[VERIFY] Error opening file: %s\n", filename_req);
        return;
    }
    FILE* fp_rsp = fopen(filename_rsp, "r");
    if (fp_rsp == NULL) {
        fprintf(stderr, "[VERIFY] Error opening file: %s\n", filename_rsp);
        fclose(fp_fax);
        return;
    }   

    bool result = true;
    int i = 0;

    int total_tests;
    switch (type) {
        case BLOCK_CIPHER_AES128:
            total_tests = AES128_TEST_CASES;
            break;
        case BLOCK_CIPHER_AES192:
            total_tests = AES192_TEST_CASES;
            break;
        case BLOCK_CIPHER_AES256:
            total_tests = AES256_TEST_CASES;
            break;
        default:
            total_tests = 0; // Unknown type
            break;
    }

    int passed_tests = 0;

    // Spinner characters for visualizing processing progress
    const char *spinner[] = {"|", "/", "-", "\\", "|", "/", "-", "\\"};
    int spinner_index = 0;


    printf("\n\n");

    char line_fax[MAX_TXT_SIZE];
    char line_rsp[MAX_TXT_SIZE];

    // printf("\r\x1b[35m[%c] Verifying test vector... \n", spinner[spinner_index]);
    int line_number = 0;
    while (fgets(line_fax, MAX_LINE_LENGTH, fp_fax) && fgets(line_rsp, MAX_LINE_LENGTH, fp_rsp)) {
        line_number++;

        // Remove trailing newline characters
        line_fax[strcspn(line_fax, "\r\n")] = '\0';
        line_rsp[strcspn(line_rsp, "\r\n")] = '\0';

        // Skip blank lines in both files
        if (strcmp(line_fax, "") == 0 && strcmp(line_rsp, "") == 0) {
            continue;
        }

        // Process only lines starting with COUNT, KEY, PT, or CT
        if (strncmp(line_fax, "COUNT =", 7) == 0 || strncmp(line_fax, "KEY =", 5) == 0 ||
            strncmp(line_fax, "PT =", 4) == 0 || strncmp(line_fax, "CT =", 4) == 0) {
            // printf("[VERIFY] Line %d\nFAX: %s\nRSP: %s\n", line_number, line_fax, line_rsp);

            if (strcmp(line_fax, line_rsp) != 0) {
                fprintf(stderr, "\n%s%s[%4d Line] Mismatch found:%s\n%sFAX: %s\n%sRSP: %s%s\n", 
                    ANSI_BOLD, ANSI_BG_RED, // %s%s
                    line_number,            // %4d  
                    ANSI_BG_DEFAULT, ANSI_FG_GREEN, // %s
                    line_fax,               // FAX: %s  
                    ANSI_FG_RED,
                    line_rsp, ANSI_RESET);
                result = false;
                break;
            }
            i++;
        }

        // usleep(5000);
        // usleep(10000); // Sleep for 10 milliseconds

        if (strncmp(line_fax, "KEY =", 5) == 0) {
            passed_tests++;
        }
        // printf("\r\x1b[35m[%s] Verifying test vector... (%3d/%3d)\r", spinner[spinner_index], passed_tests, total_tests);
        progress_bar(passed_tests, total_tests);
        spinner_index = (spinner_index + 1) % 8;
        fflush(stdout);
    }

    printf("\n\n%s[*] Test Results:\n", ANSI_FG_YELLOW);
    printf("- Total vectors : %3d\n", total_tests);
    printf("- Passed vectors: %3d%s\n", passed_tests, ANSI_RESET);
    printf("%s\n\n", result ? "\x1b[36m[O] Result: PASSED" : "\x1b[31m[X] Result: FAILED");
    printf("%s", ANSI_RESET);

    // Cleanup
    fclose(fp_fax);
    fclose(fp_rsp);
    printf("%s%s----------------------------------------- END ------------------------------------------%s%s\n",
        ANSI_BG_MAGENTA, ANSI_BOLD,
        ANSI_BG_DEFAULT, ANSI_RESET);
    printf("\n\n");
}