/* File: include/kat_verifier.h */

#include "cryptomodule_api.h"
#include "block_cipher/block_cipher_api.h"
#include "cryptomodule_utils.h"

#ifndef KAT_VERIFIER_H
#define KAT_VERIFIER_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LINE_LENGTH 3072
#define MAX_TXT_SIZE 1024

#define AES128_TEST_CASES 512
#define AES192_TEST_CASES 640
#define AES256_TEST_CASES 768
#define ARIA128_TEST_CASES 256
#define ARIA192_TEST_CASES 384
#define ARIA256_TEST_CASES 512
#define LEA128_TEST_CASES 256
#define LEA192_TEST_CASES 384
#define LEA256_TEST_CASES 512

/**
 * @brief Prints a progress bar to the console.
 * @param current Current progress value.
 * @param total Total value for the progress bar.
 * @details This function prints a progress bar to the console, indicating the current progress
 *          as a percentage of the total value.
 */
void progress_bar(int current, int total);

/**
 * @brief Parses a hexadecimal string into an array of u32 values.
 * @param dst Pointer to the destination array.
 * @param src Pointer to the source hexadecimal string.
 * @param length Length of the destination array.
 * @details This function converts a hexadecimal string into an array of u32 values.
 *          Each u32 value is represented by 8 hexadecimal characters in the string.
 *          The function assumes that the string is well-formed and contains valid hexadecimal characters.
 */
void parse_hexline(u32 *dst, const char *src, size_t length);

/**
 * @brief Converts a hexadecimal string to a byte array.
 * @param string Pointer to the hexadecimal string.
 * @param byte_array Pointer to the destination byte array.
 * @return Length of the byte array.
 * @details This function converts a hexadecimal string into a byte array.
 *          Each byte is represented by 2 hexadecimal characters in the string.
 *          The function assumes that the string is well-formed and contains valid hexadecimal characters.
 */
size_t byte_length(const char *string);

/**
 * @brief Calculates the length of a word in a string.
 * @param string Pointer to the string.
 * @return Length of the word in the string.
 * @details This function calculates the length of a word in a string.
 *          Each word is represented by 8 hexadecimal characters in the string.
 *          The function assumes that the string is well-formed and contains valid hexadecimal characters.
 */
size_t word_length(const char *string);

/**
 * @brief BlockCipherTestData structure.
 * @details This structure holds test data for block ciphers, including key, IV, plaintext, and ciphertext.
 *          It is used for KAT (Known Answer Test) verification of block cipher implementations.
 */
typedef struct __BlockCipherTestData__ {
    // BlockCipherType type; /* Type of the cipher (AES, ARIA, LEA) */
    // BlockCipherDirection dir; /* Direction of the cipher (encryption/decryption) */
    u32 *key;         /* Key for the cipher */
    u32 *iv;          /* Initialization vector */
    u32 *pt;          /* Plaintext input */
    u32 *ct;          /* Ciphertext output */
    size_t key_len;  /* Length of the key */
    size_t iv_len;   /* Length of the IV */
    size_t pt_len;   /* Length of the plaintext */
    size_t ct_len;   /* Length of the ciphertext */
} BlockCipherTestData;

/**
 * @brief Creates a BlockCipherTestData structure.
 * @param key_len Length of the key.
 * @param iv_len Length of the IV.
 * @param pt_len Length of the plaintext.
 * @param ct_len Length of the ciphertext.
 * @return Pointer to the created BlockCipherTestData structure.
 * @details This function allocates memory for the BlockCipherTestData structure and initializes its members.
 */
BlockCipherTestData *create_block_cipher_test_data(size_t key_len, size_t iv_len, size_t pt_len, size_t ct_len);

/**
 * @brief Clears the contents of a BlockCipherTestData structure.
 * @param data Pointer to the BlockCipherTestData structure to clear.
 * @details This function sets all members of the BlockCipherTestData structure to zero.
 */
void clear_block_cipher_test_data(BlockCipherTestData *data);

/**
 * @brief Deletes a BlockCipherTestData structure.
 * @param data Pointer to the BlockCipherTestData structure to delete.
 * @details This function frees the memory allocated for the BlockCipherTestData structure and its members.
 */
void delete_block_cipher_test_data(BlockCipherTestData *data);

/**
 * @brief Prints the contents of a BlockCipherTestData structure.
 * @param data Pointer to the BlockCipherTestData structure to print.
 * @details This function prints the key, IV, plaintext, and ciphertext values in a human-readable format.
 */
void print_block_cipher_test_data(const BlockCipherTestData *data);

/**
 * @brief Writes test data to a file.
 * @param fp Pointer to the file to write to.
 * @param data Pointer to the array of u32 values to write.
 * @param length Length of the array.
 * @return True if successful, false otherwise.
 * @details This function writes the contents of the specified array to the file in a human-readable format.
 *          The data is written in hexadecimal format, with each value separated by a space.
 */
void write_data(FILE *fp, const u32 *data, size_t length);

/**
 * @brief Creates a request file for KAT verification.
 * @param type Type of the block cipher (e.g., AES128/192/256, ARIA128/192/256, LEA128/192/256).
 * @param filename_fax Pointer to the input file name.
 * @param filename_req Pointer to the output request file name.
 * @details This function creates a request file for KAT verification by reading the contents of the input file
 *          and writing the relevant data to the output request file.
 */
void create_BlockCipher_KAT_ReqFile(BlockCipherType type, const char *filename_fax, const char *filename_req);

/**
 * @brief Creates a response file for KAT verification.
 * @param type Type of the block cipher (e.g., AES128/192/256, ARIA128/192/256, LEA128/192/256).
 * @param filename_req Pointer to the input request file name.
 * @param filename_rsp Pointer to the output response file name.
 * @details This function creates a response file for KAT verification by reading the contents of the input request file
 *          and writing the relevant data to the output response file.
 */
void create_BlockCipher_KAT_RspFile(BlockCipherType type, const char *filename_req, const char *filename_rsp);


/**
 * @brief Performs KAT verification for a block cipher.
 * @param type Type of the block cipher (e.g., AES128/192/256, ARIA128/192/256, LEA128/192/256).
 * @details This function performs KAT verification for the specified block cipher type by reading the test vectors
 *          from the input files and comparing them with the expected results. It prints the results to the console.
 */
void KAT_TEST_BLOCKCIPHER(BlockCipherType type);


#ifdef __cplusplus
}
#endif

#endif /* KAT_VERIFIER_H */