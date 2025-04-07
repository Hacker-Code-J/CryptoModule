/* File: src/utility */

#include "../include/utility.h"

void stringToByteArray(const char* str, u8* byteArray) {
    size_t length = strlen(str);
    for (size_t i = 0; i< length; i++) {
        sscanf(str + i * 2, "%2hhx", &byteArray[i]);
    }
}
void stringToWordArray(const char* str, u32* wordArray) {
    size_t length = strlen(str);
    for (size_t i = 0; i < length / 8; i++) {
        sscanf(str + i * 8, "%8x", &wordArray[i]);
    }
}