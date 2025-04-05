/* File: src/cryptomodule_core.c */
#include "../include/api.h"

cryptomodule_status_t cryptomodule_init(void)
{
    /* Possibly do library-wide init, e.g. RNG seed. */
    return CRYPTOMODULE_OK;
}

cryptomodule_status_t cryptomodule_cleanup(void)
{
    /* Possibly finalize or free resources. */
    return CRYPTOMODULE_OK;
}
