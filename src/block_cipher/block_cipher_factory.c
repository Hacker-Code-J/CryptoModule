/* File: src/block_cipher/block_cipher_factory.c */
#include "../../include/block_cipher/block_cipher.h"
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
