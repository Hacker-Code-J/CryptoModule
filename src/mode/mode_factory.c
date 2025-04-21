/* File: src/mode/mode_factory.c */

#include "../../include/mode/mode_api.h"
#include "../../include/mode/mode_ecb.h"

const ModeOfOperationApi* mode_factory(const char *name) {
    if (!name) return NULL;

    if (strcmp(name, "ECB") == 0) {
        return get_ecb_api();
    }
    // else if (strcmp(name, "CBC") == 0) {
    //     return get_cbc_api();
    // }
    // else if (strcmp(name, "CTR") == 0) {
    //     return get_ctr_api();
    // }
    // Add more modes as needed
    return NULL;
}