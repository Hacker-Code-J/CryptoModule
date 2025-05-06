# CryptoModule
A modular cryptography library providing block ciphers, modes of operation, RNG, hashing, MAC, KDF, key exchange, and signature functionality.

- **Block Ciphers** (AES, ARIA, LEA)
- **Modes of Operation** (ECB, CBC, CTR, GCM)
- **Random Number Generator** (CTR-DRBG)
- **Hash Functions** (SHA2, SHA3, LSH)
- **Message Authentication Code** (HMAC)
- **Key Derivation Function** (PBKDF)
- **Key Setup** ((EC)DH)
- **Signature** (RSAPSS, ECDSA, EC-KCDSA)

## Directory Overview

```
CryptoModule/
├── include/
│   ├── block/               # Headers for block ciphers
│   ├── mode/                # Headers for modes of operation
│   ├── rng/                 # Headers for RNG
│   ├── hash/                # Headers for hash functions
│   ├── mac/                 # Headers for MAC (HMAC, etc.)
│   ├── kdf/                 # Headers for KDF (PBKDF, etc.)
│   ├── keysetup/            # Headers for key exchange / ECDH
│   └── sign/                # Headers for signature algorithms
├── src/
│   ├── block/                   # Source for block ciphers
│   ├── mode/                    # Source for modes of operation
│   ├── rng/                     # Source for RNG
│   ├── hash/                    # Source for hash functions
│   ├── mac/                     # Source for MAC
│   ├── kdf/                     # Source for KDF
│   ├── keysetup/                # Source for key exchange
│   └── sign/                    # Source for signatures
├── tests/
│   ├── test_aes.c
│   ├── test_gcm.c
│   └── test_main.c
├── Makefile
└── README.md
```

### `include/`
All public-facing headers reside here, organized by cryptographic algorithm families. This helps users `#include` the relevant header files for each algorithm, e.g.:

```c
#include <block/aes.h>
#include <mode/gcm.h>
#include <rng/ctr_drbg.h>
...
```

### `src/`
Contains the `.c` source files grouped by the same categories. Each subfolder matches the corresponding subfolder in `include`.

### `tests/`
Holds unit and integration tests for each algorithm or feature. By default, the main test runner or minimal test files might be placed here. Each test typically links against the compiled library to confirm correctness.

## Building

A simplified `Makefile` is provided. You can build the static library (`libcryptomodule.a`) and test executables by running:

```bash
make
```

After building, the resulting products are typically placed in:

- `libcryptomodule.a` in the project root (or in a `build/lib` directory if your Makefile is configured so).
- Test binaries in `build/bin/` or a similar location.

## Running Tests

1. Build the tests by running `make test`.
2. Run each test binary, or run a special `run-tests` target (if provided in the Makefile) with:
   ```bash
   make run-tests
   ```
   This attempts to run all test executables in a loop.

## Usage Example

Here’s a minimal usage example in user code:

```c
#include <stdio.h>
#include <cryptomodule/block/aes.h> // For AES block cipher
#include <cryptomodule/mode/gcm.h>  // For GCM mode

int main(void) {
    // Initialize library if needed
    // cryptomodule_init(); // optional, if you have a global init

    // Example usage: AES encryption in GCM mode
    unsigned char key[16] = {0}; // For demonstration
    unsigned char iv[12]  = {0}; 
    unsigned char plaintext[64] = "Example data to encrypt.";
    unsigned char ciphertext[64];
    unsigned char tag[16];

    // ... call your AES + GCM API ...
    // e.g. gcm_encrypt(key, sizeof(key), iv, sizeof(iv),
    //                 plaintext, sizeof(plaintext),
    //                 ciphertext, tag);

    // cryptomodule_cleanup(); // optional, if you have global cleanup
    return 0;
}
```

Compile and link with:

```bash
gcc -I./include -L. -lcryptomodule your_app.c -o your_app
```

(Adjust paths and names accordingly.)

## Adding New Algorithms or Features

1. Create a header in the appropriate subdirectory under `include/`.
2. Add the implementation `.c` file in the matching subdirectory under `src/`.
3. Update or create tests in `tests/` if needed.
4. Update the Makefile if you add new subdirectories, or just rely on `wildcard src/<name>/*.c` patterns.

## License & Contributing

- [License]: (Add your license or disclaimers here)
- **Contributions**: Fork, then open a pull request describing your feature or fix.
