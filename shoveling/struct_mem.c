// gcc -g -O0 struct_mem.c -o struct_mem
#include <stdio.h>
#include <stddef.h>  // for offsetof
#include <stdint.h>

/*
    ┌─────────────────────────────────────┐
    │         BlockCipherApi              │  40 bytes total
    │-------------------------------------│
    │ Offset 0x00: name pointer           │  8 bytes
    │ Offset 0x08: init function pointer  │  8 bytes
    │ Offset 0x10: encrypt_block pointer  │  8 bytes
    │ Offset 0x18: decrypt_block pointer  │  8 bytes
    │ Offset 0x20: dispose pointer        │  8 bytes
    └─────────────────────────────────────┘

    ┌─────────────────────────────────────────────┐
    │           CipherInternal (Union)            │  536 bytes total
    │---------------------------------------------│
    │ (Option 1) AES internal (used if AES cipher)│  264 bytes (approx.)
    │  • block_size  : 8 bytes                    │
    │  • key_len     : 8 bytes                    │
    │  • round_keys  : 60 × 4 = 240 bytes         │
    │  • nr          : 4 bytes                    │
    │---------------------------------------------│
    │ (Option 2) ARIA internal (if ARIA cipher)   │  296 bytes (approx.)
    │  • block_size  : 8 bytes                    │
    │  • key_len     : 8 bytes                    │
    │  • round_keys  : 68 × 4 = 272 bytes         │
    │  • nr          : 4 bytes                    │
    │---------------------------------------------│
    │ (Option 3) LEA internal (if LEA cipher)     │  536 bytes (approx.)
    │  • block_size  : 8 bytes                    │
    │  • key_len     : 8 bytes                    │
    │  • round_keys  : 128 × 4 = 512 bytes        │
    │  • nr          : 4 bytes                    │
    └─────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────┐
    │           BlockCipherContext                    │  544 bytes total
    │-------------------------------------------------│
    │ Offset 0x0000: api pointer (8 bytes)            │   
    │ Offset 0x0008: internal_data (CipherInternal)   │  536 bytes allocated
    │             └───────────── See above ─────────┘
    └──────────────────────────────────────────────────┘

*/

typedef uint8_t u8;
typedef uint32_t u32;

/* Forward declaration */
typedef struct BlockCipherContext BlockCipherContext;

typedef struct BlockCipherApi {
    const char *name;
    int (*init)(BlockCipherContext* ctx, size_t block_size, const u8* key, size_t key_len);
    void (*encrypt_block)(BlockCipherContext* ctx, const u8* plaintext, u8* ciphertext);
    void (*decrypt_block)(BlockCipherContext* ctx, const u8* ciphertext, u8* plaintext);
    void (*dispose)(BlockCipherContext* ctx);
} BlockCipherApi;

typedef union CipherInternal {
    struct {
        size_t block_size;  /* Typically must be 16 for AES */
        size_t key_len;     /* 16, 24, or 32 for AES-128/192/256 */
        u32 round_keys[60]; 
        int nr;             /* e.g., 10 for AES-128, 12, or 14... */
    } aes_internal;
    struct {
        size_t block_size;  /* Typically must be 16 for ARIA */
        size_t key_len;     /* 16, 24, or 32 for ARIA-128/192/256 */
        u32 round_keys[68];
        int nr;             /* e.g., 12 for ARIA-128, 14, or 16... */
    } aria_internal;
    struct {
        size_t block_size;  /* Typically must be 16 for LEA */
        size_t key_len;     /* 16, 24, or 32 for LEA-128/192/256 */
        u32 round_keys[128];
        int nr;             /* e.g., 24 for LEA-128, 28, or 32... */
    } lea_internal;
} CipherInternal;

struct BlockCipherContext {
    const BlockCipherApi* api;  
    CipherInternal internal_data; /* Generic internal state for any cipher */
};

// Function to print sizes and memory layout of a single BlockCipherContext
void print_single_context_layout() {
    BlockCipherContext ctx;
    BlockCipherApi api;
    CipherInternal *ci = &ctx.internal_data;

    printf("\nSingle BlockCipherContext Layout:\n");
    printf("---------------------------------\n");

    // BlockCipherContext sizes
    printf("BlockCipherContext total size: %zu bytes\n", sizeof(BlockCipherContext));
    printf("  - api pointer: %zu bytes (address: %p)\n", sizeof(BlockCipherApi*), (void*)&ctx.api);
    printf("  - internal_data: %zu bytes (address: %p)\n", sizeof(CipherInternal), (void*)&ctx.internal_data);

    // BlockCipherApi sizes
    printf("\nBlockCipherApi total size: %zu bytes\n", sizeof(BlockCipherApi));
    printf("  - name pointer: %zu bytes (address: %p)\n", sizeof(char*), (void*)&api.name);
    printf("  - init function pointer: %zu bytes (address: %p)\n", sizeof(void*), (void*)&api.init);
    printf("  - encrypt_block function pointer: %zu bytes (address: %p)\n", sizeof(void*), (void*)&api.encrypt_block);
    printf("  - decrypt_block function pointer: %zu bytes (address: %p)\n", sizeof(void*), (void*)&api.decrypt_block);
    printf("  - dispose function pointer: %zu bytes (address: %p)\n", sizeof(void*), (void*)&api.dispose);

    // CipherInternal sizes
    printf("\nCipherInternal union total size: %zu bytes\n", sizeof(CipherInternal));

    printf("\n  AES internal struct: %zu bytes\n", sizeof(ci->aes_internal));
    printf("    - block_size: %zu bytes (address: %p)\n", sizeof(ci->aes_internal.block_size), (void*)&ci->aes_internal.block_size);
    printf("    - key_len: %zu bytes (address: %p)\n", sizeof(ci->aes_internal.key_len), (void*)&ci->aes_internal.key_len);
    printf("    - round_keys[60]: %zu bytes (address: %p)\n", sizeof(ci->aes_internal.round_keys), (void*)&ci->aes_internal.round_keys);
    printf("    - nr: %zu bytes (address: %p)\n", sizeof(ci->aes_internal.nr), (void*)&ci->aes_internal.nr);

    printf("\n  ARIA internal struct: %zu bytes\n", sizeof(ci->aria_internal));
    printf("    - block_size: %zu bytes (address: %p)\n", sizeof(ci->aria_internal.block_size), (void*)&ci->aria_internal.block_size);
    printf("    - key_len: %zu bytes (address: %p)\n", sizeof(ci->aria_internal.key_len), (void*)&ci->aria_internal.key_len);
    printf("    - round_keys[68]: %zu bytes (address: %p)\n", sizeof(ci->aria_internal.round_keys), (void*)&ci->aria_internal.round_keys);
    printf("    - nr: %zu bytes (address: %p)\n", sizeof(ci->aria_internal.nr), (void*)&ci->aria_internal.nr);

    printf("\n  LEA internal struct: %zu bytes\n", sizeof(ci->lea_internal));
    printf("    - block_size: %zu bytes (address: %p)\n", sizeof(ci->lea_internal.block_size), (void*)&ci->lea_internal.block_size);
    printf("    - key_len: %zu bytes (address: %p)\n", sizeof(ci->lea_internal.key_len), (void*)&ci->lea_internal.key_len);
    printf("    - round_keys[128]: %zu bytes (address: %p)\n", sizeof(ci->lea_internal.round_keys), (void*)&ci->lea_internal.round_keys);
    printf("    - nr: %zu bytes (address: %p)\n", sizeof(ci->lea_internal.nr), (void*)&ci->lea_internal.nr);

    printf("\n");
}
/*
Single BlockCipherContext Layout:
---------------------------------
BlockCipherContext total size: 544 bytes
  - api pointer: 8 bytes (address: 0x7ffcb2875020)
  - internal_data: 536 bytes (address: 0x7ffcb2875028)

BlockCipherApi total size: 40 bytes
  - name pointer: 8 bytes (address: 0x7ffcb2874ff0)
  - init function pointer: 8 bytes (address: 0x7ffcb2874ff8)
  - encrypt_block function pointer: 8 bytes (address: 0x7ffcb2875000)
  - decrypt_block function pointer: 8 bytes (address: 0x7ffcb2875008)
  - dispose function pointer: 8 bytes (address: 0x7ffcb2875010)

CipherInternal union total size: 536 bytes

  AES internal struct: 264 bytes
    - block_size: 8 bytes (address: 0x7ffcb2875028)
    - key_len: 8 bytes (address: 0x7ffcb2875030)
    - round_keys[60]: 240 bytes (address: 0x7ffcb2875038)
    - nr: 4 bytes (address: 0x7ffcb2875128)

  ARIA internal struct: 296 bytes
    - block_size: 8 bytes (address: 0x7ffcb2875028)
    - key_len: 8 bytes (address: 0x7ffcb2875030)
    - round_keys[68]: 272 bytes (address: 0x7ffcb2875038)
    - nr: 4 bytes (address: 0x7ffcb2875148)

  LEA internal struct: 536 bytes
    - block_size: 8 bytes (address: 0x7ffcb2875028)
    - key_len: 8 bytes (address: 0x7ffcb2875030)
    - round_keys[128]: 512 bytes (address: 0x7ffcb2875038)
    - nr: 4 bytes (address: 0x7ffcb2875238)
 */

void print_all_sizes() {
    CipherInternal ci;
    BlockCipherContext ctx;
    BlockCipherApi api;

    printf("\nStructure and Union Sizes with Addresses:\n");
    printf("-----------------------------------------\n");

    // BlockCipherApi sizes
    printf("BlockCipherApi total size: %zu bytes\n", sizeof(BlockCipherApi));
    printf("  - name pointer: %zu bytes (address: %p)\n", sizeof(char*), (void*)&api.name);
    printf("  - init function pointer: %zu bytes (address: %p)\n", sizeof(void*), (void*)&api.init);
    printf("  - encrypt_block function pointer: %zu bytes (address: %p)\n", sizeof(void*), (void*)&api.encrypt_block);
    printf("  - decrypt_block function pointer: %zu bytes (address: %p)\n", sizeof(void*), (void*)&api.decrypt_block);
    printf("  - dispose function pointer: %zu bytes (address: %p)\n", sizeof(void*), (void*)&api.dispose);

    // CipherInternal sizes
    printf("\nCipherInternal union total size: %zu bytes\n", sizeof(CipherInternal));

    printf("\n  AES internal struct: %zu bytes\n", sizeof(ci.aes_internal));
    printf("    - block_size: %zu bytes (address: %p)\n", sizeof(ci.aes_internal.block_size), (void*)&ci.aes_internal.block_size);
    printf("    - key_len: %zu bytes (address: %p)\n", sizeof(ci.aes_internal.key_len), (void*)&ci.aes_internal.key_len);
    printf("    - round_keys[60]: %zu bytes (address: %p)\n", sizeof(ci.aes_internal.round_keys), (void*)&ci.aes_internal.round_keys);
    printf("    - nr: %zu bytes (address: %p)\n", sizeof(ci.aes_internal.nr), (void*)&ci.aes_internal.nr);

    printf("\n  ARIA internal struct: %zu bytes\n", sizeof(ci.aria_internal));
    printf("    - block_size: %zu bytes (address: %p)\n", sizeof(ci.aria_internal.block_size), (void*)&ci.aria_internal.block_size);
    printf("    - key_len: %zu bytes (address: %p)\n", sizeof(ci.aria_internal.key_len), (void*)&ci.aria_internal.key_len);
    printf("    - round_keys[68]: %zu bytes (address: %p)\n", sizeof(ci.aria_internal.round_keys), (void*)&ci.aria_internal.round_keys);
    printf("    - nr: %zu bytes (address: %p)\n", sizeof(ci.aria_internal.nr), (void*)&ci.aria_internal.nr);

    printf("\n  LEA internal struct: %zu bytes\n", sizeof(ci.lea_internal));
    printf("    - block_size: %zu bytes (address: %p)\n", sizeof(ci.lea_internal.block_size), (void*)&ci.lea_internal.block_size);
    printf("    - key_len: %zu bytes (address: %p)\n", sizeof(ci.lea_internal.key_len), (void*)&ci.lea_internal.key_len);
    printf("    - round_keys[128]: %zu bytes (address: %p)\n", sizeof(ci.lea_internal.round_keys), (void*)&ci.lea_internal.round_keys);
    printf("    - nr: %zu bytes (address: %p)\n", sizeof(ci.lea_internal.nr), (void*)&ci.lea_internal.nr);

    // BlockCipherContext sizes
    printf("\nBlockCipherContext total size: %zu bytes\n", sizeof(BlockCipherContext));
    printf("  - api pointer: %zu bytes (address: %p)\n", sizeof(BlockCipherApi*), (void*)&ctx.api);
    printf("  - internal_data: %zu bytes (address: %p)\n", sizeof(CipherInternal), (void*)&ctx.internal_data);
    printf("\n");
}
/*
Structure and Union Sizes with Addresses:
-----------------------------------------
BlockCipherApi total size: 40 bytes
  - name pointer: 8 bytes (address: 0x7ffc0e0bea00)
  - init function pointer: 8 bytes (address: 0x7ffc0e0bea08)
  - encrypt_block function pointer: 8 bytes (address: 0x7ffc0e0bea10)
  - decrypt_block function pointer: 8 bytes (address: 0x7ffc0e0bea18)
  - dispose function pointer: 8 bytes (address: 0x7ffc0e0bea20)

CipherInternal union total size: 536 bytes

  AES internal struct: 264 bytes
    - block_size: 8 bytes (address: 0x7ffc0e0bea30)
    - key_len: 8 bytes (address: 0x7ffc0e0bea38)
    - round_keys[60]: 240 bytes (address: 0x7ffc0e0bea40)
    - nr: 4 bytes (address: 0x7ffc0e0beb30)

  ARIA internal struct: 296 bytes
    - block_size: 8 bytes (address: 0x7ffc0e0bea30)
    - key_len: 8 bytes (address: 0x7ffc0e0bea38)
    - round_keys[68]: 272 bytes (address: 0x7ffc0e0bea40)
    - nr: 4 bytes (address: 0x7ffc0e0beb50)

  LEA internal struct: 536 bytes
    - block_size: 8 bytes (address: 0x7ffc0e0bea30)
    - key_len: 8 bytes (address: 0x7ffc0e0bea38)
    - round_keys[128]: 512 bytes (address: 0x7ffc0e0bea40)
    - nr: 4 bytes (address: 0x7ffc0e0bec40)

BlockCipherContext total size: 544 bytes
  - api pointer: 8 bytes (address: 0x7ffc0e0bec50)
  - internal_data: 536 bytes (address: 0x7ffc0e0bec58)
*/

// Function to print a visual representation of memory layout
void print_memory_layout_visual() {
    printf("\n+-------------------- MEMORY LAYOUT VISUALIZATION --------------------+\n");
    
    // BlockCipherApi visualization
    printf("| BlockCipherApi (%zu bytes total)                                        |\n", sizeof(BlockCipherApi));
    printf("+------------------------------------------------------------------------+\n");
    printf("| +------------------+                                                    |\n");
    printf("| | name        | 0x00-0x%02zx (%zu bytes)                                   |\n", 
           sizeof(char*)-1, sizeof(char*));
    printf("| +------------------+                                                    |\n");
    printf("| | init        | 0x%02zx-0x%02zx (%zu bytes)                                  |\n", 
           offsetof(BlockCipherApi, init), 
           offsetof(BlockCipherApi, init) + sizeof(void*) - 1, 
           sizeof(void*));
    printf("| +-----------------------+                                                    |\n");
    printf("| | encrypt_blk | 0x%02zx-0x%02zx (%zu bytes)                                  |\n", 
           offsetof(BlockCipherApi, encrypt_block), 
           offsetof(BlockCipherApi, encrypt_block) + sizeof(void*) - 1,
           sizeof(void*));
    printf("| +-----------------------+                                                    |\n");
    printf("| | decrypt_blk | 0x%02zx-0x%02zx (%zu bytes)                                  |\n", 
           offsetof(BlockCipherApi, decrypt_block), 
           offsetof(BlockCipherApi, decrypt_block) + sizeof(void*) - 1,
           sizeof(void*));
    printf("| +-----------------------+                                                    |\n");
    printf("| | dispose     | 0x%02zx-0x%02zx (%zu bytes)                                  |\n", 
           offsetof(BlockCipherApi, dispose), 
           offsetof(BlockCipherApi, dispose) + sizeof(void*) - 1,
           sizeof(void*));
    printf("| +-----------------------+                                                    |\n");
    
    // CipherInternal visualization
    printf("+------------------------------------------------------------------------+\n");
    printf("| CipherInternal Union (%zu bytes total)                                  |\n", sizeof(CipherInternal));
    printf("+------------------------------------------------------------------------+\n");
    printf("| +--------------------------------------------------------------+       |\n");
    printf("| | AES structure                                                |       |\n");
    printf("| +--------------------------------------------------------------+       |\n");
    printf("| | block_size    | 0x00-0x%02zx                                  |       |\n", 
           sizeof(size_t)-1);
    printf("| +--------------------------------------------------------------+       |\n");
    printf("| | key_len       | 0x%02zx-0x%02zx                                 |       |\n", 
           offsetof(CipherInternal, aes_internal.key_len), 
           offsetof(CipherInternal, aes_internal.key_len) + sizeof(size_t) - 1);
    printf("| +--------------------------------------------------------------+       |\n");
    printf("| | round_keys[60]| 0x%02zx-0x%02zx (%zu bytes)                  |       |\n", 
           offsetof(CipherInternal, aes_internal.round_keys), 
           offsetof(CipherInternal, aes_internal.round_keys) + sizeof(u32[60]) - 1,
           sizeof(u32[60]));
    printf("| +--------------------------------------------------------------+       |\n");
    printf("| | nr            | 0x%02zx-0x%02zx                                 |       |\n", 
           offsetof(CipherInternal, aes_internal.nr), 
           offsetof(CipherInternal, aes_internal.nr) + sizeof(int) - 1);
    printf("| +--------------------------------------------------------------+       |\n");
    
    // BlockCipherContext visualization
    printf("+------------------------------------------------------------------------+\n");
    printf("| BlockCipherContext (%zu bytes total)                                    |\n", sizeof(BlockCipherContext));
    printf("+------------------------------------------------------------------------+\n");
    printf("| +------------------+                                                    |\n");
    printf("| | api         | 0x00-0x%02zx (%zu bytes)                                   |\n", 
           sizeof(BlockCipherApi*)-1, sizeof(BlockCipherApi*));
    printf("| +------------------+                                                    |\n");
    printf("| |             |                                                         |\n");
    printf("| | internal    |                                                         |\n");
    printf("| |    data     | 0x%02zx-0x%02zx (%zu bytes)                             |\n", 
           offsetof(BlockCipherContext, internal_data), 
           sizeof(BlockCipherContext) - 1,
           sizeof(CipherInternal));
    printf("| |             |                                                         |\n");
    printf("| +------------------+                                                    |\n");
    printf("+------------------------------------------------------------------------+\n");
}

// Print memory layout of the CipherInternal union and its components
void print_cipher_internal_layout() {
    CipherInternal ci;
    
    printf("\nCipherInternal union size: %zu bytes\n", sizeof(CipherInternal));
    
    printf("\nAES internal structure:\n");
    printf("  Offset of block_size: %zu bytes\n", offsetof(CipherInternal, aes_internal.block_size));
    printf("  Offset of key_len: %zu bytes\n", offsetof(CipherInternal, aes_internal.key_len));
    printf("  Offset of round_keys: %zu bytes\n", offsetof(CipherInternal, aes_internal.round_keys));
    printf("  Offset of nr: %zu bytes\n", offsetof(CipherInternal, aes_internal.nr));
    printf("  Size of round_keys array: %zu bytes\n", sizeof(ci.aes_internal.round_keys));
    
    printf("\nARIA internal structure:\n");
    printf("  Offset of block_size: %zu bytes\n", offsetof(CipherInternal, aria_internal.block_size));
    printf("  Offset of key_len: %zu bytes\n", offsetof(CipherInternal, aria_internal.key_len));
    printf("  Offset of round_keys: %zu bytes\n", offsetof(CipherInternal, aria_internal.round_keys));
    printf("  Offset of nr: %zu bytes\n", offsetof(CipherInternal, aria_internal.nr));
    printf("  Size of round_keys array: %zu bytes\n", sizeof(ci.aria_internal.round_keys));
    
    printf("\nLEA internal structure:\n");
    printf("  Offset of block_size: %zu bytes\n", offsetof(CipherInternal, lea_internal.block_size));
    printf("  Offset of key_len: %zu bytes\n", offsetof(CipherInternal, lea_internal.key_len));
    printf("  Offset of round_keys: %zu bytes\n", offsetof(CipherInternal, lea_internal.round_keys));
    printf("  Offset of nr: %zu bytes\n", offsetof(CipherInternal, lea_internal.nr));
    printf("  Size of round_keys array: %zu bytes\n", sizeof(ci.lea_internal.round_keys));
}

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
    // print_single_context_layout();
    print_all_sizes();
    // print_cipher_internal_layout();
    // print_memory_layout_visual();

    // BlockCipherApi api_example;
    // BlockCipherContext ctx_example;

    // printf("BlockCipherApi size: %zu bytes\n", sizeof(BlockCipherApi));
    // printf("Offset of name in BlockCipherApi: %zu bytes\n", offsetof(BlockCipherApi, name));
    // printf("Offset of init in BlockCipherApi: %zu bytes\n", offsetof(BlockCipherApi, init));
    // printf("Offset of encrypt_block in BlockCipherApi: %zu bytes\n", offsetof(BlockCipherApi, encrypt_block));

    // printf("\nBlockCipherContext size: %zu bytes\n", sizeof(BlockCipherContext));
    // printf("Offset of api in BlockCipherContext: %zu bytes\n", offsetof(BlockCipherContext, api));
    // printf("Offset of internal_data in BlockCipherContext: %zu bytes\n", offsetof(BlockCipherContext, internal_data));

    // static const BlockCipherApi aes_api = {
    //     .name = "AES",
    //     .init = aes_init,
    //     .encrypt_block = aes_encrypt,
    //     .decrypt_block = aes_decrypt,
    //     .dispose = aes_dispose,
    // };

    // printf("\nMemory layout of aes_api:\n");
    // printf("Address of aes_api: %p\n", (void*)&aes_api);
    // printf("Address of aes_api.name: %p (size: %zu bytes)\n", (void*)&aes_api.name, sizeof(aes_api.name));
    // printf("Address of aes_api.init: %p (size: %zu bytes)\n", (void*)&aes_api.init, sizeof(aes_api.init));
    // printf("Address of aes_api.encrypt_block: %p (size: %zu bytes)\n", (void*)&aes_api.encrypt_block, sizeof(aes_api.encrypt_block));
    // printf("Address of aes_api.decrypt_block: %p (size: %zu bytes)\n", (void*)&aes_api.decrypt_block, sizeof(aes_api.decrypt_block));
    // printf("Address of aes_api.dispose: %p (size: %zu bytes)\n", (void*)&aes_api.dispose, sizeof(aes_api.dispose));

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
- Bytes 0-7 correspond to the name pointer.
- Bytes 8-15 represent the init function pointer.
- Bytes 16-23 hold the address for encrypt_block.
- Bytes 24-31 hold the decrypt_block pointer.
- Bytes 32-39 hold the dispose function pointer.
For the BlockCipherContext structure:
- The first 8 bytes (offset 0) contain the api pointer.
-The remaining 256 bytes (offsets 8 to 263) are for internal_data.

By running these commands in gdb, you can see the ��raw�� memory representation of your variables 
as they exist in real memory at runtime. This can help you understand how your structures are laid out and 
verify that the fields are stored in the order and sizes you expect.
*/