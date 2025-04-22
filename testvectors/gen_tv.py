#!/usr/bin/env python3
import re

INPUT_FILE  = "./block_cipher_tv/nist_aes/CBCVarTxt256.rsp"           # your original file
OUTPUT_FILE = "./block_cipher_tv/nist_aes/re_CBCVarTxt256.fax"  # new file with fixed COUNTs
OFFSET      = 256

def bump_counts(inp_path, out_path, offset):
    # Matches lines like "COUNT = 3" (with any spaces around "=")
    pattern = re.compile(r'^(COUNT\s*=\s*)(\d+)\s*$', re.MULTILINE)

    with open(inp_path, 'r') as fin, open(out_path, 'w') as fout:
        for line in fin:
            m = pattern.match(line)
            if m:
                old = int(m.group(2))
                new = old + offset
                # write exactly one newline after the updated COUNT line
                fout.write(f"{m.group(1)}{new}\n")
            else:
                fout.write(line)

if __name__ == "__main__":
    bump_counts(INPUT_FILE, OUTPUT_FILE, OFFSET)
    print(f"Done – wrote COUNTs+{OFFSET} into {OUTPUT_FILE}")
