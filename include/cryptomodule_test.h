/* File: include/kat_verifier.h */

#include "api.h"
#include "block_cipher/block_cipher.h"
#include "cryptomodule_utils.h"

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
typedef struct __TestData__ {
    u32* key;   // Pointer for arbitrary length key
    u32* iv;    // Pointer for arbitrary length IV
    u32* pt;    // Pointer for arbitrary length plaintext
    u32* ct;    // Pointer for arbitrary length ciphertext
    size_t key_len; // Length of the key
    size_t iv_len;  // Length of the IV
    size_t pt_len;  // Length of the plaintext
    size_t ct_len;  // Length of the ciphertext
} TestData;

/**
 * @brief Prints the contents of a TestData structure.
 * @param data Pointer to the TestData structure to print.
 */
void print_TestData(const TestData *data);

/**
 * @brief Prints a progress bar to the console.
 * @param current Current progress value.
 * @param total Total value for the progress bar.
 */
void progress_bar(int current, int total);

/**
 * @brief Frees the memory allocated for a TestData structure.
 * @param data Pointer to the TestData structure to free.
 */
void free_TestData(TestData *data);

/**
 * @brief Parses a hexadecimal string into an array of u32 values.
 * @param dst Pointer to the destination array.
 * @param src Pointer to the source hexadecimal string.
 * @param length Length of the destination array.
 */
void parse_hexline(u32 *dst, const char* src, size_t length);

/**
 * @brief Calculates the length of a word in a string.
 * @param string Pointer to the string.
 * @return Length of the word in the string.
 */
size_t word_length(const char *string);

/**
 * @brief Converts a hexadecimal string to a byte array.
 * @param string Pointer to the hexadecimal string.
 * @param byte_array Pointer to the destination byte array.
 * @return Length of the byte array.
 */
size_t byte_length(const char *string);

/**
 * @brief Reads test data from a file.
 * @param fp Pointer to the file to read from.
 * @param data Pointer to the TestData structure to fill.
 * @return True if successful, false otherwise.
 * @details This function reads the contents of the specified file and fills the TestData structure with the parsed data.
 *          The file is expected to contain key, IV, plaintext, and ciphertext data in a specific format.
 *          The function allocates memory for the key, IV, plaintext, and ciphertext arrays based on the data read from the file.
 *          The key, IV, plaintext, and ciphertext are typically provided in a specific format,
 *          such as hexadecimal or binary, and the function ensures that the data is read correctly into the structure.
 *          The function returns true if the read operation is successful, and false otherwise. 
 */
bool read_TestData(FILE *fp, TestData *data);

/**
 * @brief Writes test data to a file.
 * @param fp Pointer to the file to write to.
 * @param data Pointer to the array of u32 values to write.
 * @param length Length of the array.
 * @return True if successful, false otherwise.
 * @details This function writes the contents of the data array to the specified file.
 *          The data is written in a specific format, typically as hexadecimal values.
 *          The length parameter specifies the number of u32 values to write.
 *          The function returns true if the write operation is successful, and false otherwise.
 *          This function is useful for saving test data to a file for later use or verification.
 *          It allows for easy storage and retrieval of test data, making it convenient for KAT verification.
 *          The data is typically written in a specific format, such as hexadecimal or binary,
 *          and the function ensures that the data is written correctly to the file.
 */
void write_TestData(FILE *fp, const u32 *data, size_t length);

/**
 * @brief Compares two TestData structures for equality.
 * @param data1 Pointer to the first TestData structure.
 * @param data2 Pointer to the second TestData structure.
 * @return True if the structures are equal, false otherwise.
 * @details This function compares the contents of two TestData structures to determine if they are equal.
 *          The comparison is done by checking the key, IV, plaintext, and ciphertext values,
 *          as well as their respective lengths. If all values match, the function returns true.
 *          Otherwise, it returns false. This function is useful for verifying the correctness of KATs
 *          by comparing the expected and actual results.
 *          The function ensures that the key, IV, plaintext, and ciphertext values are compared correctly,
 *          taking into account their lengths and data types. It provides a simple and efficient way
 *          to verify the correctness of cryptographic algorithms by comparing the expected and actual results.
 *          The function can be used in conjunction with KAT verification functions to ensure the correctness
 *          of cryptographic algorithms. It provides a clear and organized way to compare the test data
 *          and determine if the KAT verification is successful.
 */
bool compare_TestData(const TestData *data1, const TestData* data2);

/**
 * @brief Creates a request file for KAT verification.
 * @param filename_fax Pointer to the input file name.
 * @param filename_req Pointer to the output request file name.
 * @details This function creates a request file for KAT verification by reading the contents of the input file
 *          and writing the relevant data to the output request file. The function handles memory allocation
 *          and file operations as needed.
 */
void create_BlockCipher_KAT_ReqFile(const char* filename_fax, const char* filename_req);

/**
 * @brief Creates a response file for KAT verification.
 * @param filename_req Pointer to the input request file name.
 * @param filename_rsp Pointer to the output response file name.
 * @details This function creates a response file for KAT verification by reading the contents of the input request file
 *          and writing the relevant data to the output response file. The function handles memory allocation
 *          and file operations as needed.
 */
void create_BlockCipher_KAT_RspFile(const char* filename_req, const char* filename_rsp);

/**
 * @brief Performs KAT verification for AES block cipher.
 * @param filename_fax Pointer to the input file name.
 * @param filename_req Pointer to the output request file name.
 * @param filename_rsp Pointer to the output response file name.
 * @details This function performs KAT verification for the AES block cipher by reading the contents of the input file
 *          and comparing the expected and actual results. The function handles memory allocation
 *          and file operations as needed.
 */
void KAT_TEST_BLOCKCIPHER_AES(void);
// void KAT_TEST_BLOCKCIPHER_AES(const char* filename, const BlockCipherApi* aes_api, TestData* data);

#ifdef __cplusplus
}
#endif

#endif /* KAT_VERIFIER_H */