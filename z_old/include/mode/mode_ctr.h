/* FILE: include/mode/mode_ctr.h */
#ifndef MODE_CTR_H
#define MODE_CTR_H

#include "api_mode.h"
#include "../block_cipher/api_block_cipher.h"
// #include "../block_cipher/block_cipher_aes.h"
// #include "../block_cipher/block_cipher_aria.h"
// #include "../block_cipher/block_cipher_lea.h"
// #include "../cryptomodule_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

const ModeOfOperationApi* get_ctr_api(void);

#ifdef __cplusplus
}
#endif
#endif /* MODE_CTR_H */