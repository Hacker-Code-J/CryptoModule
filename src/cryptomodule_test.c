/* File: src/kat_verifier.c */

#include "../include/cryptomodule_test.h"
#include "../include/cryptomodule_utils.h"
#include "../include/block_cipher/block_cipher_api.h"
#include "../include/block_cipher/block_cipher_aes.h"

void print_TestData(const TestData *data) {
    if (data == NULL) {
        printf("TestData is NULL\n");
        return;
    }
    // printf("Key Length: %zu\n", data->key_len);
    // printf("IV Length: %zu\n", data->iv_len);
    // printf("Plaintext Length: %zu\n", data->pt_len);
    // printf("Ciphertext Length: %zu\n", data->ct_len);

    printf("Key: ");
    for (size_t i = 0; i < data->key_len; i++) {
        printf("%08X ", data->key[i]);
    }
    printf("\n");

    printf("IV: ");
    for (size_t i = 0; i < data->iv_len; i++) {
        printf("%08X ", data->iv[i]);
    }
    printf("\n");

    printf("Plaintext: ");
    for (size_t i = 0; i < data->pt_len; i++) {
        printf("%08X ", data->pt[i]);
    }
    printf("\n");

    // printf("Ciphertext: ");
    for (size_t i = 0; i < data->ct_len; i++) {
        printf("%08x", data->ct[i]);
    }
    printf("\n");
}

void progress_bar(int current, int total) {
    int width = 50; // Width of the progress bar
    float progress = (float)current / total;
    int pos = width * progress;

    // ANSI Escape Codes for colors
    const char* GREEN = "\x1b[32m";
    const char* YELLOW = "\x1b[33m";
    const char* RED = "\x1b[31m";
    const char* RESET = "\x1b[0m";

    printf("\r[");
    for (int i = 0; i < width; ++i) {
        if (i < pos) printf("%s=", GREEN); // White for completed part
        else if (i == pos) printf("%s>", YELLOW); // Yellow for current position
        else printf("%s ", RED); // Red for remaining part
    }
    printf("%s] %d%% (%d/%d)", RESET, (int)(progress * 100.0), current, total);    
}

void free_TestData(TestData *data) {
    if (data) {
        free(data->key);
        free(data->iv);
        free(data->pt);
        free(data->ct);
    }
    data = NULL;
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

bool read_TestData(FILE *fp, TestData *data) {
    char line[MAX_LINE_LENGTH];
    size_t key_len = 0, iv_len = 0, pt_len = 0, ct_len = 0;

    // Read the key
    if (fgets(line, sizeof(line), fp) != NULL) {
        key_len = word_length(line);
        data->key = (u32*)malloc(key_len * sizeof(u32));
        parse_hexline(data->key, line, key_len);
    }
    // Read the IV
    if (fgets(line, sizeof(line), fp) != NULL) {
        iv_len = word_length(line);
        data->iv = (u32*)malloc(iv_len * sizeof(u32));
        parse_hexline(data->iv, line, iv_len);
    }
    // Read the plaintext
    if (fgets(line, sizeof(line), fp) != NULL) {
        pt_len = word_length(line);
        data->pt = (u32*)malloc(pt_len * sizeof(u32));
        parse_hexline(data->pt, line, pt_len);
    }
    // Read the ciphertext
    if (fgets(line, sizeof(line), fp) != NULL) {
        ct_len = word_length(line);
        data->ct = (u32*)malloc(ct_len * sizeof(u32));
        parse_hexline(data->ct, line, ct_len);
    }

    data->key_len = key_len;
    data->iv_len = iv_len;
    data->pt_len = pt_len;
    data->ct_len = ct_len;

    return true;
}

void write_TestData(FILE *fp, const u32 *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        fprintf(fp, "%08X", data[i]);
    }
    fprintf(fp, "\n");
}

bool compare_TestData(const TestData *data1, const TestData *data2) {
    if (data1->key_len != data2->key_len || 
        data1->iv_len != data2->iv_len || 
        data1->pt_len != data2->pt_len || 
        data1->ct_len != data2->ct_len) {
        return false;
    }

    if (memcmp(data1->key, data2->key, data1->key_len * sizeof(u32)) != 0 ||
        memcmp(data1->iv, data2->iv, data1->iv_len * sizeof(u32)) != 0 ||
        memcmp(data1->pt, data2->pt, data1->pt_len * sizeof(u32)) != 0 ||
        memcmp(data1->ct, data2->ct, data1->ct_len * sizeof(u32)) != 0) {
        return false;
    }

    return true;
}

void create_BlockCipher_KAT_ReqFile(const char *filename_fax, const char *filename_req) {
    FILE *fp_fax, *fp_req;
    char *line;
    size_t bufsize = MAX_LINE_LENGTH;

    printf("[REQ] Creating request file: %s\n", filename_req);
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
        if (strncmp(line, "COUNT =", 7) == 0) {
            fputs(line, fp_req);
        }
        if (strncmp(line, "KEY =", 5) == 0) {
            fputs(line, fp_req);
        } else if (strncmp(line, "PT =", 4) == 0) {
            fputs(line, fp_req);
            fputs("\n", fp_req);
        } 
        // else {
        //     fprintf(stderr, "Unknown line format: %s\n", line);
        // }
    } // while

    free(line);
    fclose(fp_fax);
    fclose(fp_req);
    printf("Created request file: %s\n", filename_req);
}

void create_BlockCipher_KAT_RspFile(const char *filename_req, const char *filename_rsp) {
    FILE *fp_req, *fp_rsp;
    char *line;
    size_t bufsize = MAX_LINE_LENGTH;
    int is_first_key = 1;

    // Read the request file and create the response file
    printf("[RSP] Creating response file: %s\n", filename_rsp);
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

    TestData* data = (TestData*)malloc(sizeof(TestData));
    if (data == NULL) {
        fprintf(stderr, "[RSP] Memory allocation error\n");
        return;
    }
    memset(data, 0, sizeof(TestData));

    BlockCipherContext ctx;
    clear_block_cipher_ctx(&ctx);
    // memset(&ctx, 0, sizeof(BlockCipherContext));
    ctx.api = block_cipher_factory("AES");
    if (ctx.api == NULL) {
        fprintf(stderr, "[RSP] No AES API available.\n");
        free(line);
        fclose(fp_req);
        fclose(fp_rsp);
        free_TestData(data);
        return;
    }

    while (fgets(line, bufsize, fp_req)) {
        if (strncmp(line, "COUNT =", 7) == 0) {
            if (!is_first_key) {
                fputc('\n', fp_rsp);
            } is_first_key = 0;
            fprintf(fp_rsp, "%s", line);
        } else if (strncmp(line, "KEY =", 5) == 0) {
            if (ctx.api->dispose) {
                ctx.api->dispose(&ctx);
            }
            // printf("[RSP] KEY: %s", line);
            data->key_len = word_length(line + 6);
            data->key = (u32*)malloc(data->key_len * sizeof(u32));
            if (data->key == NULL) {
                fprintf(stderr, "[RSP] Memory allocation error\n");
                free(line);
                fclose(fp_req);
                fclose(fp_rsp);
                free_TestData(data);
                return;
            }
            parse_hexline(data->key, line + 6, data->key_len);
            fputs(line, fp_rsp);
        } else if (strncmp(line, "PT =", 4) == 0) {
            data->pt_len = word_length(line + 5);
            data->ct_len = word_length(line + 5);
            data->pt = (u32*)malloc(data->pt_len * sizeof(u32));
            if (data->pt == NULL) {
                fprintf(stderr, "[RSP] Memory allocation error\n");
                free(line);
                fclose(fp_req);
                fclose(fp_rsp);
                free_TestData(data);
                return;
            }
            parse_hexline(data->pt, line + 5, data->pt_len);
            fputs(line, fp_rsp);
        } else {
            data->ct = (u32*)malloc(data->ct_len * sizeof(u32));
            if (data->ct == NULL) {
                fprintf(stderr, "[RSP] Memory allocation error\n");
                free(line);
                fclose(fp_req);
                fclose(fp_rsp);
                free_TestData(data);
                return;
            }
            u8 key[AES128_KEY_SIZE] = { 0x00, };
            u8 byte_data[AES_BLOCK_SIZE] = { 0x00, };
            u8 encrypted_byte_data[AES_BLOCK_SIZE] = { 0x00, };
            word2byte(data->key, key);
            word2byte(data->pt, byte_data);


            fprintf(fp_rsp, "CT = ");
            // Initialize AES context
            if (ctx.api->init(&ctx, 
                              key, 
                              data->key_len * sizeof(u32), 
                              data->pt_len * sizeof(u32), 
                              BLOCK_CIPHER_ENCRYPTION) != BLOCK_CIPHER_OK_INITIALIZATION) {
                fprintf(stderr, "[RSP] AES init failed (maybe invalid block/key size)\n");
                free(line);
                fclose(fp_req);
                fclose(fp_rsp);
                free_TestData(data);
                return;
            }
            // memset(key, 0, sizeof(key));

            // Encrypt the plaintext
            ctx.api->process_block(&ctx, byte_data, encrypted_byte_data, BLOCK_CIPHER_ENCRYPTION);
            byte2word(encrypted_byte_data, data->ct);
            for (size_t i = 0; i < data->ct_len; i++) {
                fprintf(fp_rsp, "%08x", data->ct[i]);
            } 
            fprintf(fp_rsp, "\n");
            if (ctx.api->dispose) {
                ctx.api->dispose(&ctx);
            }
            // printf("CT: ");
            // for (size_t i = 0; i < data->ct_len; i++) {
            //     printf("%08X ", data->ct[i]);
            // }
            // printf("\n");
        }
    }

    if (ctx.api->dispose) {
        ctx.api->dispose(&ctx);
    }

    // print_TestData(data);

    free_TestData(data);
    free(line);
    fclose(fp_req);
    fclose(fp_rsp);
    printf("Created response file: %s\n", filename_rsp);
}

void KAT_TEST_BLOCKCIPHER_AES(void) {
    // Current working directory: ../CryptoModule
    const char* file_path = "./testvectors/block_cipher_tv/nist_aes/";
    char filename_fax[100];
    char filename_req[100];
    char filename_rsp[100];

    snprintf(filename_fax, sizeof(filename_fax), "%s%s", file_path, "ECBVarKey128_ENC.fax");
    snprintf(filename_req, sizeof(filename_req), "%s%s", file_path, "ECBVarKey128_ENC.req");
    snprintf(filename_rsp, sizeof(filename_rsp), "%s%s", file_path, "ECBVarKey128_ENC.rsp");


    create_BlockCipher_KAT_ReqFile(filename_fax, filename_req);
    create_BlockCipher_KAT_RspFile(filename_req, filename_rsp);

    printf("\n START: KAT_TEST_BLOCKCIPHER_AES\n");
    printf("  Request file: %s\n", filename_req);
    printf("  Response file: %s\n", filename_rsp);
    printf("  Test data file: %s\n", filename_fax);
    
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

    TestData* data_fax = (TestData*)malloc(sizeof(TestData));
    TestData* data_rsp = (TestData*)malloc(sizeof(TestData));
    
    if (data_fax == NULL || data_rsp == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        if (data_fax) free(data_fax);
        if (data_rsp) free(data_rsp);
        fclose(fp_fax);
        fclose(fp_rsp);
        return;
    }

    memset(data_fax, 0, sizeof(TestData));
    memset(data_rsp, 0, sizeof(TestData));
    
    bool result = true;
    int i = 0;
    int total_tests = 128;
    int passed_tests = 0;

    printf("\nVerifying test vectors...\n");

    while (i < total_tests) {
        memset(data_fax, 0, sizeof(TestData));
        memset(data_rsp, 0, sizeof(TestData));

        if (!read_TestData(fp_fax, data_fax) || !read_TestData(fp_rsp, data_rsp)) {
            fprintf(stderr, "Error reading test data at vector %d\n", i + 1);
            result = false;
            break;
        }

        if (!compare_TestData(data_fax, data_rsp)) {
            fprintf(stderr, "\nTest vector %d failed verification\n", i + 1);
            printf("[%d-th Error!!!]\n", i);
            printf("Expected Key: ");
            for (size_t j = 0; j < data_fax->key_len; j++) {
                printf("%08x", data_fax->key[j]);
            }
            printf("\nActual Key  : ");
            for (size_t j = 0; j < data_rsp->key_len; j++) {
                printf("%08x", data_rsp->key[j]);
            }
            printf("\nExpected PT : ");
            for (size_t j = 0; j < data_fax->pt_len; j++) {
                printf("%08x", data_fax->pt[j]);
            }
            printf("\nActual PT   : ");
            for (size_t j = 0; j < data_rsp->pt_len; j++) {
                printf("%08x", data_rsp->pt[j]);
            }
            printf("\nExpected CT : ");
            for (size_t j = 0; j < data_fax->ct_len; j++) {
                printf("%08x", data_fax->ct[j]);
            }
            printf("\nActual CT   : ");
            for (size_t j = 0; j < data_rsp->ct_len; j++) {
                printf("%08x", data_rsp->ct[j]);
            }
            

            // printf("Expected: "); print_TestData(data_fax);
            // printf("Actual  : "); print_TestData(data_rsp);
            result = false;
            break;
        }

        // usleep(50000); // Sleep for 50 milliseconds to slow down the progress bar
        // usleep(10000); // Sleep for 10 milliseconds to slow down the progress bar


        free_TestData(data_fax);
        free_TestData(data_rsp);
        passed_tests++;
        i++;
        
        progress_bar(i, total_tests);
        fflush(stdout);
    }

    printf("\n\nTest Results:\n");
    printf("Total vectors: %d\n", total_tests);
    printf("Passed vectors: %d\n", passed_tests);
    printf("Result: %s\n\n", result ? "PASSED" : "FAILED");

    // Cleanup
    fclose(fp_fax);
    fclose(fp_rsp);
}