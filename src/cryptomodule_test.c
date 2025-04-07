/* File: src/kat_verifier.c */

#include "../include/kat_verifier.h"
#include "../include/utility.h"
#include "../include/block_cipher/block_cipher.h"
#include "../include/block_cipher/block_cipher_aes.h"

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

void free_TestData(TestData* data) {
    if (data) {
        free(data->key);
        free(data->iv);
        free(data->pt);
        free(data->ct);
    }
}

void parse_hexline(u32* dst, const char* src, size_t length) {
    size_t i = 0;
    char* endptr;
    char* token = strtok((char*)src, " ");
    while (token != NULL && i < length) {
        dst[i++] = (u32)strtoul(token, &endptr, 16);
        if (*endptr != '\0' && *endptr != '\n') {
            fprintf(stderr, "Error parsing hex string: %s\n", token);
            break;
        }
        token = strtok(NULL, " ");
    }
}

size_t word_length(const char* string) {
    size_t length = 0;
    while (string[length] != '\0' && string[length] != '\n') {
        length++;
    }
    return length;
}

size_t byte_length(const char* string) {
    size_t length = 0;
    while (string[length] != '\0' && string[length] != '\n') {
        length++;
    }
    return length / 2; // Each byte is represented by two hex characters
}

bool read_TestData(FILE* fp, TestData* data) {
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

void write_TestData(FILE* fp, const u32* data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        fprintf(fp, "%08X ", data[i]);
    }
    fprintf(fp, "\n");
}

bool compare_TestData(const TestData* data1, const TestData* data2) {
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

void create_BlockCipher_AES_ReqFile(const char* filename_fax, const char* filename_req) {
    FILE *fp_fax, *fp_req;
    char* line;
    size_t bufsize = MAX_LINE_LENGTH;
    int is_first_key = 1;

    fp_fax = fopen(filename_fax, "r");
    if (fp_fax == NULL) {
        fprintf(stderr, "Error opening file: %s\n", filename_fax);
        return;
    }

    fp_req = fopen(filename_req, "w");
    if (fp_req == NULL) {
        fprintf(stderr, "Error opening file: %s\n", filename_req);
        fclose(fp_fax);
        return;
    }

    line = (char*)malloc(bufsize * sizeof(char));
    if (line == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        fclose(fp_fax);
        fclose(fp_req);
        return;
    }

    while (fgets(line, bufsize, fp_fax) != NULL) {
        if (strncmp(line, "KEY =", 5) == 0) {
            if (!is_first_key) {
                fprintf(fp_req, "\n");
            } is_first_key = 0;
            fputs(line, fp_req);
        } else if (strncmp(line, "PT =", 4) == 0) {
            fputs(line, fp_req);
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

void create_BlockCipher_AES_RspFile(const char* filename_fax, const char* filename_rsp) {
    FILE *fp_req, *fp_rsp;
    char* line;
    size_t bufsize = MAX_LINE_LENGTH;
    int is_first_key = 1;
    size_t data_len = 0;

    TestData* data = (TestData*)malloc(sizeof(TestData));
    if (data == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        return;
    }
    memset(data, 0, sizeof(TestData));

    fp_req = fopen(filename_fax, "r");
    if (fp_req == NULL) {
        fprintf(stderr, "Error opening file: %s\n", filename_fax);
        free(data);
        return;
    }
    fp_rsp = fopen(filename_rsp, "w");
    if (fp_rsp == NULL) {
        fprintf(stderr, "Error opening file: %s\n", filename_rsp);
        fclose(fp_req);
        free(data);
        return;
    }
    line = (char*)malloc(bufsize * sizeof(char));
    if (line == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        fclose(fp_req);
        fclose(fp_rsp);
        free(data);
        return;
    }

    while(fgets(line, bufsize, fp_req)) {
        if (strncmp(line, "KEY =", 5) == 0) {
            if (!is_first_key) {
                fprintf(fp_rsp, "\n");
            } is_first_key = 0;
            size_t key_len = byte_length(line + 6);
            data->key = (u8*)malloc(key_len * sizeof(u8));
            if (data->key == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                free(line);
                fclose(fp_req);
                fclose(fp_rsp);
                free(data);
                return;
            }
            parse_hexline(data->key, line + 6, key_len);
            fputs(line, fp_rsp);
        } else if (strncmp(line, "PT =", 4) == 0) {
            data_len = byte_length(line + 5);
            data->pt = (u8*)malloc(data_len * sizeof(u8));
            if (data->pt == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                free(line);
                fclose(fp_req);
                fclose(fp_rsp);
                free(data);
                return;
            }
            parse_hexline(data->pt, line + 5, data_len);
            fputs(line, fp_rsp);
        } else {
            data->ct = (u8*)malloc(data_len * sizeof(u8));
            if (data->ct == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                free(line);
                fclose(fp_req);
                fclose(fp_rsp);
                free(data);
                return;
            }
            fprintf(fp_rsp, "CT = ");
            
        }
    }
}

void KAT_TEST_BLOCKCIPHER_AES(const char* filename, const BlockCipherApi* aes_api, TestData* data) {
    // const char* AES_KAT_FOLDER_PATH = "../testvectors/block_cipher_tv/aes/";
    // char filename_fax[50];
    // char filename_rsp[50];
    // snprintf(filename_fax, sizeof(filename_fax), "%s", AES_KAT_FOLDER_PATH, "AES128(ECB)KAT.fax");
    // snprintf(filename_rsp, sizeof(filename_rsp), "%s", AES_KAT_FOLDER_PATH, "AES128(ECB)KAT.rsp");


    // create_BlockCipher_AES_TestData(filename, data);
    // if (!data->key || !data->iv || !data->pt || !data->ct) {
    //     fprintf(stderr, "Error: Test data is not properly initialized.\n");
    //     return;
    // }
    // FILE* fp = fopen(filename, "r");
    // if (!fp) {
    //     fprintf(stderr, "Error opening file: %s\n", filename);
    //     return;
    // }
    // TestData test_data;
}