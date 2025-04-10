## 1. Using AES-128-CBC Mode

AES in CBC mode requires an IV. If you want to use an IV of all zeros (matching your plaintext), you can do so. One important note is that by default OpenSSL adds a header (and salt), so you should disable that with the **-nosalt** option.

### Step-by-Step

1. **Create a file for your plaintext.**  
   One easy method is to convert your hex representation into binary. For example:

   ```bash
   echo "00000000000000000000000000000000" | xxd -r -p > pt.bin
   ```

   This creates a file `pt.bin` containing 16 bytes of zeros.

2. **Encrypt the file using OpenSSL.**  
   Now run:

   ```bash
   openssl enc -aes-128-cbc -in pt.bin -out ct.bin -K 00000000a58869d74be5a374cf867cfb -iv 00000000000000000000000000000000 -nosalt
   ```

   **Breakdown of the options:**  
   - **enc**: Use the encryption utility.  
   - **-aes-128-cbc**: Use AES with a 128-bit key in CBC mode.  
   - **-in pt.bin**: Input file with your plaintext.  
   - **-out ct.bin**: Output file for the ciphertext.  
   - **-K**: Provide the key in hex.  
   - **-iv**: Provide the IV in hex (here all zeros).  
   - **-nosalt**: Prevent OpenSSL from adding a salt header to the encrypted file.

3. **View the ciphertext in hexadecimal.**  
   You can use `xxd` to convert the ciphertext file to hex:

   ```bash
   xxd -p ct.bin
   ```

---

## 2. Using AES-128-ECB Mode

If you¡¯d prefer to use ECB mode (which does not use an IV), you can skip the IV parameter. Note that ECB mode is generally not recommended for serious cryptographic needs because it does not randomize identical blocks, but it can be useful for tests.

### Step-by-Step

1. **Create your plaintext file** (same as before):

   ```bash
   echo "00000000000000000000000000000000" | xxd -r -p > pt.bin
   ```

2. **Encrypt with OpenSSL using ECB mode.**

   ```bash
   openssl enc -aes-128-ecb -in pt.bin -out ct.bin -K 00000000a58869d74be5a374cf867cfb -nosalt
   ```

   Here we use **-aes-128-ecb** and omit the IV.

3. **Display the output ciphertext in hex:**

   ```bash
   xxd -p ct.bin
   ```

---

### A Few Extra Notes

- **Choosing the mode:**  
  CBC mode (with a proper IV) is generally more secure than ECB mode for real-world data encryption. Use ECB only for simple tests.

- **-nosalt:**  
  Without the `-nosalt` option, OpenSSL inserts an 8-byte header (the ASCII string "Salted__" followed by the salt), which would change your output. Since you¡¯re working with raw hex keys and plaintext, disabling the salt is usually preferable.

- **Key/IV Format:**  
  Ensure that the key and IV are provided as hexadecimal strings with no spaces or other delimiters.

By following these steps, you can easily encrypt your given plaintext with your specified key using OpenSSL in Linux.