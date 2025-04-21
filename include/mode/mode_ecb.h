/* File: include/mode/mode_ecb.h */

#ifndef MODE_ECB_H
#define MODE_ECB_H
#include "mode_api.h"
#include "../block_cipher/block_cipher_api.h"
#include "../block_cipher/block_cipher_aes.h"
#include "../block_cipher/block_cipher_aria.h"
#include "../block_cipher/block_cipher_lea.h"
#include "../cryptomodule_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

const ModeOfOperationApi* get_ecb_api(void);


#ifdef __cplusplus
}
#endif
#endif /* MODE_ECB_H */