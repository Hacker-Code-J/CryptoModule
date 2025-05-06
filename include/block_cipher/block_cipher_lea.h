/* FILE: include/block_cipher/block_cipher_lea.h */
#ifndef BLOCK_CIPHER_LEA_H
#define BLOCK_CIPHER_LEA_H
#include "api_block_cipher.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Get the LEA block cipher vtable. */
const BlockCipherApi* get_lea_api(void);

void lea_set_encrypt_key(const u8 *key, size_t bytes, u32 *rk);
void lea_set_decrypt_key(const u8 *key, size_t bytes, u32 *rk);
void lea_encrypt(const u8 *in, u8 *out, const u32 *rk, int r);
void lea_decrypt(const u8 *in, u8 *out, const u32 *rk, int r);

#ifdef __cplusplus
}
#endif
#endif /* BLOCK_CIPHER_LEA_H */