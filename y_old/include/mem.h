/* include/mem.h */

#include "config.h"

#ifndef MEM_H
#define MEM_H

/**
 * @file mem.h
 * @brief Header file for memory-related functions.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compare two memory blocks for equality.
 * 
 * This function compares two memory blocks of specified length and returns
 * 0 if they are equal, or a non-zero value if they differ.
 * 
 * @param in_a Pointer to the first memory block.
 * @param in_b Pointer to the second memory block.
 * @param len Length of the memory blocks to compare.
 * @return 0 if equal, non-zero if different.
 */
int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len);


#ifdef __cplusplus
}
#endif

#endif // MEM_H