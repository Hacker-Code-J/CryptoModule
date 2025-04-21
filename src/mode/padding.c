/* File: src/mode/padding.c */

#include "../../include/mode/mode_api.h"

/**
 * PKCS#7 padding:
 * - Pad length = N where N = block_size - (data_len % block_size), 1 <= N <= block_size
 * - Append N bytes, each of value N.
 */

/* Apply PKCS#7 padding.
 * buf must have room for data_len + block_size.
 * Returns total length after padding (a multiple of block_size). */
size_t pkcs7_pad(u8 *buf, size_t data_len, size_t block_size) {
    if (block_size == 0 || block_size > 255) return 0;
    size_t pad_len = block_size - (data_len % block_size);
    if (pad_len == 0) pad_len = block_size;
    for (size_t i = 0; i < pad_len; i++) {
        buf[data_len + i] = (u8)pad_len;
    }
    return data_len + pad_len;
}

/* Remove PKCS#7 padding.
 * buf_len must be ≥ block_size and a multiple of block_size.
 * On success returns new length (data without padding), or 0 on invalid padding. */
size_t pkcs7_unpad(u8 *buf, size_t buf_len, size_t block_size) {
    if (buf_len == 0 || buf_len % block_size != 0) return 0;
    u8 pad_len = buf[buf_len - 1];
    if (pad_len == 0 || pad_len > block_size) return 0;
    /* Verify padding bytes */
    for (size_t i = 0; i < pad_len; i++) {
        if (buf[buf_len - 1 - i] != pad_len) return 0;
    }
    return buf_len - pad_len;
}

/**
 * ANSI X9.23 padding:
 * - Pad length = N where N = block_size - (data_len % block_size), 1 <= N <= block_size
 * - Fill first N-1 padding bytes with zeros, last byte = N
 */

/* Apply ANSI X9.23 padding.
 * buf must have room for data_len + block_size.
 * Returns total length after padding. */
size_t ansi923_pad(u8 *buf, size_t data_len, size_t block_size) {
    if (block_size == 0 || block_size > 255) return 0;
    size_t pad_len = block_size - (data_len % block_size);
    if (pad_len == 0) pad_len = block_size;
    /* zeros for first pad_len - 1 bytes */
    memset(buf + data_len, 0x00, pad_len - 1);
    /* last byte = pad_len */
    buf[data_len + pad_len - 1] = (u8)pad_len;
    return data_len + pad_len;
}

/* Remove ANSI X9.23 padding.
 * Returns new length (without padding), or 0 on error. */
size_t ansi923_unpad(u8 *buf, size_t buf_len, size_t block_size) {
    if (buf_len == 0 || buf_len % block_size != 0) return 0;
    u8 pad_len = buf[buf_len - 1];
    if (pad_len == 0 || pad_len > block_size) return 0;
    /* Optionally, verify the N−1 bytes before pad_len are zero */
    for (size_t i = 1; i < pad_len; i++) {
        if (buf[buf_len - 1 - i] != 0x00) return 0;
    }
    return buf_len - pad_len;
}

/**
 * ISO/IEC 7816‑4 padding (a.k.a. “bit‑padding”):
 * - Always append 0x80 (1000 0000), then as many 0x00 bytes as needed to fill
 *   to a multiple of block_size.
 */

/* Apply ISO/IEC 7816‑4 padding.
 * buf must have room for data_len + block_size.
 * Returns total length after padding. */
size_t iso7816_4_pad(u8 *buf, size_t data_len, size_t block_size) {
    if (block_size == 0) return 0;
    size_t pad_len = block_size - (data_len % block_size);
    if (pad_len == 0) pad_len = block_size;
    buf[data_len] = 0x80;
    if (pad_len > 1) {
        memset(buf + data_len + 1, 0x00, pad_len - 1);
    }
    return data_len + pad_len;
}

/* Remove ISO/IEC 7816‑4 padding.
 * Returns new length (without padding), or 0 on error. */
size_t iso7816_4_unpad(u8 *buf, size_t buf_len, size_t block_size) {
    if (buf_len == 0 || buf_len % block_size != 0) return 0;
    /* Scan backwards for 0x80 marker */
    size_t i = buf_len - 1;
    while (buf[i] == 0x00) {
        i--;
    }
    if (buf[i] != 0x80) {
        return 0;  // Marker not found or bad padding
    }
    return (size_t)i;
}