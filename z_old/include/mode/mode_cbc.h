/* File: include/mode/mode_cbc.h */

#ifndef MODE_CBC_H
#define MODE_CBC_H

#include "api_mode.h"
#include "../block_cipher/api_block_cipher.h"
#include "../block_cipher/block_cipher_aes.h"
#include "../block_cipher/block_cipher_aria.h"
#include "../block_cipher/block_cipher_lea.h"
#include "../cryptomodule_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

const ModeOfOperationApi* get_cbc_api(void);

#ifdef __cplusplus
}
#endif
#endif /* MODE_CBC_H */