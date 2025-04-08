/* File: include/kat_verifier.h */

#include "api.h"
#include "block_cipher/block_cipher.h"
#include "utility.h"

#ifndef KAT_VERIFIER_H
#define KAT_VERIFIER_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LINE_LENGTH 9999
#define MAX_TXT_SIZE 1028

/**
 * @brief Structure to hold test data for KAT verification.
 * @details This structure contains pointers to the key, IV, plaintext, and ciphertext,
 *          along with their respective lengths. The key and IV can be of arbitrary length.
 *          The plaintext and ciphertext are also of arbitrary length, allowing for flexible testing.
 *          This structure is used to facilitate the verification of known answer tests (KATs)
 *          for cryptographic algorithms.
 *          The key, IV, plaintext, and ciphertext are represented as arrays of 32-bit unsigned integers (u32).
 *          The lengths of these arrays are stored in the key_len, iv_len, pt_len, and ct_len fields.
 *          This structure is designed to be used in conjunction with KAT verification functions
 *          to ensure the correctness of cryptographic algorithms.
 *          The key and IV are typically used for encryption and decryption operations,
 *          while the plaintext and ciphertext are the input and output data for these operations.
 *          The structure allows for easy access to the test data and simplifies the process of KAT verification.
 *          The key_len, iv_len, pt_len, and ct_len fields are used to specify the lengths of the respective arrays,
 *          allowing for flexible handling of different key and IV sizes, as well as varying plaintext and ciphertext lengths.
 *          This structure is essential for performing KAT verification in a consistent and efficient manner.
 *          It provides a clear and organized way to manage the test data needed for cryptographic algorithm validation.
 *          The use of u32 arrays allows for efficient storage and manipulation of the key, IV, plaintext, and ciphertext data.
 *          This structure is designed to be used in conjunction with KAT verification functions
 *          to ensure the correctness of cryptographic algorithms.
 *          The key, IV, plaintext, and ciphertext are typically provided in a specific format,
 *          such as hexadecimal or binary, and the structure allows for easy conversion and processing of this data.
 *          The key_len, iv_len, pt_len, and ct_len fields are used to specify the lengths of the respective arrays,
 *          allowing for flexible handling of different key and IV sizes, as well as varying plaintext and ciphertext lengths.
 *          This structure is essential for performing KAT verification in a consistent and efficient manner.
 *          It provides a clear and organized way to manage the test data needed for cryptographic algorithm validation.
 */
typedef struct {
    u32* key;   // Pointer for arbitrary length key
    u32* iv;    // Pointer for arbitrary length IV
    u32* pt;    // Pointer for arbitrary length plaintext
    u32* ct;    // Pointer for arbitrary length ciphertext
    size_t key_len; // Length of the key
    size_t iv_len;  // Length of the IV
    size_t pt_len;  // Length of the plaintext
    size_t ct_len;  // Length of the ciphertext
} TestData;

void progress_bar(int current, int total);

void free_TestData(TestData* data);
void parse_hexline(u32* dst, const char* src, size_t length);
size_t word_length(const char* string);
size_t byte_length(const char* string);

bool read_TestData(FILE* fp, TestData* data);
void write_TestData(FILE* fp, const u32* data, size_t length);
bool compare_TestData(const TestData* data1, const TestData* data2);

void create_BlockCipher_KAT_ReqFile(const char* filename_fax, const char* filename_req);
void create_BlockCipher_KAT_RspFile(const char* filename_req, const char* filename_rsp);
// void KAT_TEST_BLOCKCIPHER_AES(const char* filename, const BlockCipherApi* aes_api, TestData* data);
void KAT_TEST_BLOCKCIPHER_AES(void);

#ifdef __cplusplus
}
#endif

#endif /* KAT_VERIFIER_H */