#!/usr/bin/env python3
"""
entropy_claim_assessment.py

Assesses a byte stream against ENISA ACM's QUANTITATIVE randomness thresholds and
exposes the gap that the Section 7.1 statistical-testing approach creates.

It reports, for each relevant threshold, THREE numbers:
  (a) TRUE secret min-entropy of the construction
        - for a published-key keystream this is 0 (fully determined),
  (b) the min-entropy an OUTPUT-based estimator credits
        - SP800-90B 6.3.1 "most common value" estimator run on the OUTPUT
          (which is the wrong place to run it; SP800-90B requires the RAW noise
           source) -> near-maximal for any CSPRNG, true or fake,
  (c) the STRUCTURAL bit-length of the parameter
        - e.g. AES-256 key = 256 bits.

The point: ENISA's entropy thresholds (seed >=125 / >=188) get FALSELY CREDITED
by (b); its size thresholds (CTR_DRBG key >=192, symmetric >=192, hash >=384,
MAC >=192) are MET by (c) regardless of secrecy. A fully predictable stream
therefore "passes" the quantitative bar while carrying no entropy.

Usage:
  python3 entropy_claim_assessment.py <stream.bin> [--public-key] [--key-bits 256]
  --public-key  : the construction's key is published -> TRUE min-entropy = 0
                  (omit for a genuine source; TRUE is then 'unknown / source-modeled')
"""
import sys, math, argparse
from collections import Counter

Z99 = 2.576  # 99% one-sided-ish bound used by SP800-90B MCV estimator

def mcv_min_entropy_per_symbol(counts, n, sym_bits):
    pmax = max(counts) / n
    pu = min(1.0, pmax + Z99 * math.sqrt(pmax * (1 - pmax) / (n - 1)))
    h = -math.log2(pu)                # bits of min-entropy per sym_bits-wide symbol
    return h, pmax, pu

def per_bit_min_entropy(data):
    ones = 0; total = 0
    for b in data:
        for i in range(8):
            ones += (b >> i) & 1; total += 1
    c0, c1 = total - ones, ones
    h, pmax, pu = mcv_min_entropy_per_symbol([c0, c1], total, 1)
    return h, pmax

def per_byte_min_entropy(data):
    cnt = Counter(data)
    counts = list(cnt.values())
    h, pmax, pu = mcv_min_entropy_per_symbol(counts, len(data), 8)
    return h, pmax

def row(req, kind, threshold, true_val, credited_val, met_by_size, verdict, note):
    return dict(req=req, kind=kind, threshold=threshold, true=true_val,
                credited=credited_val, size_met=met_by_size, verdict=verdict, note=note)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--public-key", action="store_true",
                    help="construction key is published -> TRUE secret min-entropy = 0")
    ap.add_argument("--key-bits", type=int, default=256, help="structural key size (default 256, AES-256)")
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    n = len(data)
    h_bit, pmax_bit = per_bit_min_entropy(data)
    h_byte, pmax_byte = per_byte_min_entropy(data)

    # credited min-entropy for a seed drawn from this output, by the output-based MCV estimator
    cred_256 = h_bit * 256
    cred_384 = h_bit * 384

    true_str = "0 (key is published; output fully determined)" if args.public_key else "unknown (must be source-modeled)"
    true_seed = 0.0 if args.public_key else None

    print(f"# stream: {args.file}  ({n} bytes, {n*8} bits)")
    print(f"# output-based MCV min-entropy (SP800-90B 6.3.1, run on OUTPUT = wrong place):")
    print(f"#   per-bit  : {h_bit:.4f} bits/bit   (p_max={pmax_bit:.5f})")
    print(f"#   per-byte : {h_byte:.4f} bits/byte (p_max={pmax_byte:.6f})")
    print(f"# TRUE secret min-entropy of construction: {true_str}\n")

    rows = []
    # --- entropy-type thresholds (the falsely-credited ones) ---
    rows.append(row("DRBG seed min-entropy (Note 68)", "entropy", "125 bits",
        f"{true_seed if true_seed is not None else '?'}",
        f"{cred_256:.0f} (256-bit draw, output-MCV)",
        "n/a",
        "FALSELY CREDITED AS MET" if args.public_key else "depends on source model",
        "credited >=125 by output estimator / by passing §7.1 statistical tests; TRUE may be 0"))
    rows.append(row("DRBG seed min-entropy, quantum (Note 69)", "entropy", "188 bits",
        f"{true_seed if true_seed is not None else '?'}",
        f"{cred_256:.0f} (256-bit draw) / {cred_384:.0f} (384-bit draw)",
        "n/a",
        "FALSELY CREDITED AS MET" if args.public_key else "depends on source model",
        "a 256-bit draw is credited ~%.0f bits >= 188 by the output estimator; TRUE may be 0" % cred_256))
    # --- size-type thresholds (met by construction, secrecy irrelevant) ---
    rows.append(row("CTR_DRBG block-cipher key (Note 71)", "size", "192 bits",
        "n/a (size check)", "n/a", f"{args.key_bits} bits",
        "MET BY SIZE" if args.key_bits >= 192 else "below size",
        "this is a bit-length check; AES-256 satisfies it even with a PUBLIC key"))
    rows.append(row("Symmetric key / block cipher (Notes 3/19)", "size", "192 bits",
        "0 secret bits (if from this RNG)", "n/a", f"{args.key_bits} bits",
        "MET BY SIZE" if args.key_bits >= 192 else "below size",
        "a key generated from this RNG has the requested SIZE but inherits 0 secret entropy"))
    rows.append(row("Hash output (Note 4)", "size", "384 bits",
        "n/a", "n/a", "depends on chosen hash",
        "MECHANISM-LEVEL",
        "property of the hash algorithm selected downstream, not of the RNG output"))
    rows.append(row("MAC key, hash-based (Note 19)", "size", "192 bits",
        "0 secret bits (if from this RNG)", "n/a", f"{args.key_bits} bits",
        "MET BY SIZE" if args.key_bits >= 192 else "below size",
        "size met; secret entropy inherited from RNG = 0 for the published-key fake"))

    print(f"{'requirement':42s} {'type':7s} {'thr':9s} {'verdict'}")
    print("-" * 100)
    for r in rows:
        print(f"{r['req']:42s} {r['kind']:7s} {r['threshold']:9s} {r['verdict']}")
        print(f"{'':42s} -> {r['note']}")
    print()
    if args.public_key:
        print("CONCLUSION: construction has 0 true secret min-entropy, yet")
        print("  * entropy thresholds (>=125 / >=188) are FALSELY CREDITED via the §7.1")
        print("    statistical-testing path and output-based estimation, and")
        print("  * size thresholds (>=192 / >=384) are MET BY CONSTRUCTION (length, not secrecy).")
        print("  => a fully predictable RNG clears ENISA's quantitative randomness bar.")

if __name__ == "__main__":
    main()
