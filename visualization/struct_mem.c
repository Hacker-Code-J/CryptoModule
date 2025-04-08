// gcc -g -O0 struct_mem.c -o struct_mem
#include <stdio.h>
#include <stddef.h>  // for offsetof
#include <stdint.h>

typedef uint8_t u8;

/* Forward declaration */
typedef struct BlockCipherContext BlockCipherContext;

typedef struct BlockCipherApi {
    const char *name;
    int (*init)(BlockCipherContext* ctx, size_t block_size, const u8* key, size_t key_len);
    void (*encrypt_block)(BlockCipherContext* ctx, const u8* plaintext, u8* ciphertext);
    void (*decrypt_block)(BlockCipherContext* ctx, const u8* ciphertext, u8* plaintext);
    void (*dispose)(BlockCipherContext* ctx);
} BlockCipherApi;

struct BlockCipherContext {
    const BlockCipherApi *api;
    u8 internal_data[256];
};

static int  aes_init(BlockCipherContext *ctx, size_t block_size, const u8 *key, size_t key_len);
static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct);
static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt);
static void aes_dispose(BlockCipherContext *ctx);

static int  aes_init(BlockCipherContext *ctx, size_t block_size, const u8 *key, size_t key_len) {
    return 0;
}
static void aes_encrypt(BlockCipherContext *ctx, const u8 *pt, u8 *ct) {

}
static void aes_decrypt(BlockCipherContext *ctx, const u8 *ct, u8 *pt) {

}
static void aes_dispose(BlockCipherContext *ctx) {

}

int main(void) {
    BlockCipherApi api_example;
    BlockCipherContext ctx_example;

    printf("BlockCipherApi size: %zu bytes\n", sizeof(BlockCipherApi));
    printf("Offset of name in BlockCipherApi: %zu bytes\n", offsetof(BlockCipherApi, name));
    printf("Offset of init in BlockCipherApi: %zu bytes\n", offsetof(BlockCipherApi, init));
    printf("Offset of encrypt_block in BlockCipherApi: %zu bytes\n", offsetof(BlockCipherApi, encrypt_block));

    printf("\nBlockCipherContext size: %zu bytes\n", sizeof(BlockCipherContext));
    printf("Offset of api in BlockCipherContext: %zu bytes\n", offsetof(BlockCipherContext, api));
    printf("Offset of internal_data in BlockCipherContext: %zu bytes\n", offsetof(BlockCipherContext, internal_data));

    static const BlockCipherApi aes_api = {
        .name = "AES",
        .init = aes_init,
        .encrypt_block = aes_encrypt,
        .decrypt_block = aes_decrypt,
        .dispose = aes_dispose,
    };

    printf("\nMemory layout of aes_api:\n");
    printf("Address of aes_api: %p\n", (void*)&aes_api);
    printf("Address of aes_api.name: %p (size: %zu bytes)\n", (void*)&aes_api.name, sizeof(aes_api.name));
    printf("Address of aes_api.init: %p (size: %zu bytes)\n", (void*)&aes_api.init, sizeof(aes_api.init));
    printf("Address of aes_api.encrypt_block: %p (size: %zu bytes)\n", (void*)&aes_api.encrypt_block, sizeof(aes_api.encrypt_block));
    printf("Address of aes_api.decrypt_block: %p (size: %zu bytes)\n", (void*)&aes_api.decrypt_block, sizeof(aes_api.decrypt_block));
    printf("Address of aes_api.dispose: %p (size: %zu bytes)\n", (void*)&aes_api.dispose, sizeof(aes_api.dispose));

    return 0;
}

/*
Part A. ---------------------------------------------------------------------

pwndbg> print &api_example 
$1 = (BlockCipherApi *) 0x7fffffffd200

pwndbg> x/40xb &api_example
0x7fffffffd200: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd208: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd210: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd218: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd220: 0x00    0x00    0x80    0x04    0x00    0x00    0x00    0x00

pwndbg> print &api_example.name
$2 = (const char **) 0x7fffffffd200

pwndbg> x/8xb 0x7fffffffe200+8
0x7fffffffe208: 0x6e    0x6e    0x61    0x6d    0x6f    0x6e    0x00    0x4c

Part B. ---------------------------------------------------------------------

pwndbg> print &ctx_example
$3 = (BlockCipherContext *) 0x7fffffffd230

For API:
pwndbg> x/8xb &ctx_example
0x7fffffffd230: 0x40    0x00    0x00    0x00    0x00    0x00    0x00    0x00

pwndbg> print &ctx_example.internal_data
$4 = (u8 (*)[256]) 0x7fffffffd238

pwndbg> x/256xb (char *)ctx_example.internal_data
0x7fffffffd238: 0x08    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd240: 0x40    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd248: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd250: 0xff    0xff    0xff    0xff    0xff    0xff    0xff    0xff
0x7fffffffd258: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd260: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd268: 0x19    0x00    0x00    0x00    0x21    0x00    0x00    0x00
0x7fffffffd270: 0x02    0x00    0x00    0x00    0x10    0x00    0x00    0x00
0x7fffffffd278: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd280: 0x02    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd288: 0x06    0x00    0x00    0x00    0x00    0x00    0x00    0x80
0x7fffffffd290: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd298: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2a0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2a8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2b0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2b8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2c0: 0x0d    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2c8: 0x01    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2d0: 0x01    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2d8: 0x01    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2e0: 0x40    0x40    0x55    0x55    0x55    0x55    0x00    0x00
0x7fffffffd2e8: 0x3c    0x28    0xfe    0xf7    0xff    0x7f    0x00    0x00
0x7fffffffd2f0: 0x30    0x0d    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd2f8: 0x89    0xd8    0xff    0xff    0xff    0x7f    0x00    0x00
0x7fffffffd300: 0x00    0x10    0xfc    0xf7    0xff    0x7f    0x00    0x00
0x7fffffffd308: 0x00    0x00    0x00    0x01    0x01    0x01    0x00    0x00
0x7fffffffd310: 0x02    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd318: 0xff    0xfb    0x8b    0x17    0x00    0x00    0x00    0x00
0x7fffffffd320: 0x99    0xd8    0xff    0xff    0xff    0x7f    0x00    0x00
0x7fffffffd328: 0x64    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffd330: 0x00    0x10    0x00    0x00    0x00    0x00    0x00    0x00


Part C. ---------------------------------------------------------------------
Interpreting the Output:

The x/40xb command displays 40 bytes starting from the given address in hexadecimal (each byte labeled).

For the BlockCipherApi structure:
- Bytes 0?7 correspond to the name pointer.
- Bytes 8?15 represent the init function pointer.
- Bytes 16?23 hold the address for encrypt_block.
- Bytes 24?31 hold the decrypt_block pointer.
- Bytes 32?39 hold the dispose function pointer.
For the BlockCipherContext structure:
- The first 8 bytes (offset 0) contain the api pointer.
-The remaining 256 bytes (offsets 8 to 263) are for internal_data.

By running these commands in gdb, you can see the ¡°raw¡± memory representation of your variables 
as they exist in real memory at runtime. This can help you understand how your structures are laid out and 
verify that the fields are stored in the order and sizes you expect.
*/