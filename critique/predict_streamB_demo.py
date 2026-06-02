#!/usr/bin/env python3
"""
predict_streamB_demo.py

Self-contained restatement of the predict_streamB.py construction from
github.com/owlmt/ais31-full-evaluation, included so this repository's
Section 7.1 demonstration is runnable on its own.

It emits an AES-256-CTR keystream produced from a PUBLISHED key and a PUBLISHED
nonce. The output:
  * has zero secret entropy (the key is printed below),
  * is reproducible byte-for-byte by anyone who reads this file, and
  * passes the statistical-testing approach of ENISA ACM Section 7.1
    (see battery.py and the measured results in SECTION_7.1_CRITIQUE.md).

If you prefer, point run_demo.sh at the original predict_streamB.py instead;
the construction is identical.

Requires: pycryptodome  (pip install pycryptodome)
Usage:    python3 predict_streamB_demo.py <out.bin> [num_bytes]
"""
import sys
from Crypto.Cipher import AES
from Crypto.Util import Counter

# ---- PUBLISHED PARAMETERS (no secret) --------------------------------------
KEY   = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")  # 256-bit, PUBLIC
NONCE = bytes.fromhex("000000000000000000000000")                         # 96-bit prefix, PUBLIC

def keystream(num_bytes: int) -> bytes:
    ctr = Counter.new(32, prefix=NONCE, initial_value=0)
    return AES.new(KEY, AES.MODE_CTR, counter=ctr).encrypt(b"\x00" * num_bytes)

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "fakeB.bin"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 1_250_000  # 10,000,000 bits
    with open(out, "wb") as f:
        f.write(keystream(n))
    print(f"wrote {out}: {n} bytes ({n*8} bits) of PREDICTABLE keystream")
    print(f"  key   (PUBLIC): {KEY.hex()}")
    print(f"  nonce (PUBLIC): {NONCE.hex()}")
    print("  -> anyone can regenerate this exact file; it carries no entropy.")

if __name__ == "__main__":
    main()
