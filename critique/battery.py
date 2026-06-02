#!/usr/bin/env python3
"""
battery.py - statistical "randomness" tests for the Section 7.1 demonstration.

Purpose: show that a fully PREDICTABLE stream (AES-256-CTR keystream from a
PUBLISHED key) passes the statistical-testing approach that ENISA ACM Section 7.1
lists as a way to "assess the quality of the output of a random source".

It implements:
  --mode simple  : FIPS 140-2 / AIS31-flavoured quick battery
                   (monobit, 4-bit poker, runs, longest-run)
  --mode sp80022 : a faithful subset of NIST SP800-22
                   (monobit, block-frequency, runs, longest-run-of-ones,
                    cumulative-sums, approximate-entropy, serial,
                    and DFT/spectral if numpy is available)

Reads bytes from a file or stdin. A test PASSES at significance alpha (default
0.01) when its p-value >= alpha (or, for the simple FIPS tests, when the
statistic falls in the documented acceptance interval).

This script deliberately makes NO claim about entropy or unpredictability.
That is the entire point of the demonstration.
"""
import sys, math, argparse

# ---- pure-Python special functions (no scipy dependency) -------------------
def erfc(x):
    return math.erfc(x)

def igamc(a, x):
    """Regularized upper incomplete gamma Q(a,x) = gammaincc(a,x).
    Numerical Recipes gser/gcf; good enough for p-values here."""
    if x < 0 or a <= 0:
        return 1.0
    if x == 0:
        return 1.0
    if x < a + 1.0:
        # series
        ap = a
        s = 1.0 / a
        d = s
        for _ in range(1000):
            ap += 1.0
            d *= x / ap
            s += d
            if abs(d) < abs(s) * 1e-15:
                break
        return 1.0 - s * math.exp(-x + a * math.log(x) - math.lgamma(a))
    else:
        # continued fraction
        FPMIN = 1e-300
        b = x + 1.0 - a
        c = 1.0 / FPMIN
        d = 1.0 / b
        h = d
        for i in range(1, 1000):
            an = -i * (i - a)
            b += 2.0
            d = an * d + b
            if abs(d) < FPMIN:
                d = FPMIN
            c = b + an / c
            if abs(c) < FPMIN:
                c = FPMIN
            d = 1.0 / d
            de = d * c
            h *= de
            if abs(de - 1.0) < 1e-15:
                break
        return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h

def bits_from_bytes(data):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

# ---- simple FIPS 140-2 / AIS31-style battery -------------------------------
def simple_battery(data):
    bits = bits_from_bytes(data)
    n = len(bits)
    res = []

    ones = sum(bits)
    # FIPS 140-2 monobit acceptance (scaled): expect ~n/2, allow 3 sigma
    sigma = math.sqrt(n) / 2.0
    lo, hi = n / 2 - 3 * sigma, n / 2 + 3 * sigma
    res.append(("monobit", lo <= ones <= hi, f"ones={ones} expect[{lo:.0f},{hi:.0f}]"))

    # 4-bit poker
    m = 4
    k = n // m
    counts = [0] * 16
    for i in range(k):
        v = 0
        for j in range(m):
            v = (v << 1) | bits[i * m + j]
        counts[v] += 1
    X = (16.0 / k) * sum(c * c for c in counts) - k
    # chi-square df=15, accept 1.03 < X < 57.4 (FIPS-style wide interval)
    res.append(("poker4", 1.03 < X < 57.4, f"X={X:.2f} accept(1.03,57.4)"))

    # runs test (count maximal runs)
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1
    exp = (2.0 * ones * (n - ones)) / n + 1
    sd = math.sqrt((exp - 1) * (exp - 2) / (n - 1)) if n > 2 else 1
    z = abs(runs - exp) / sd if sd else 0
    res.append(("runs", z < 3.0, f"runs={runs} z={z:.2f} (|z|<3)"))

    # longest run of ones
    longest = cur = 0
    for b in bits:
        cur = cur + 1 if b == 1 else 0
        longest = max(longest, cur)
    # heuristic ceiling ~ 2*log2(n)+10
    ceil = 2 * math.log2(n) + 10 if n > 1 else 64
    res.append(("longrun", longest <= ceil, f"longest={longest} ceil={ceil:.0f}"))
    return res

# ---- SP800-22 subset -------------------------------------------------------
def sp_monobit(bits):
    n = len(bits)
    s = sum(1 if b else -1 for b in bits)
    p = erfc(abs(s) / math.sqrt(n) / math.sqrt(2))
    return ("frequency_monobit", p)

def sp_block_frequency(bits, M=128):
    n = len(bits)
    N = n // M
    if N == 0:
        return ("block_frequency", 1.0)
    chi = 0.0
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        pi = sum(block) / M
        chi += (pi - 0.5) ** 2
    chi *= 4 * M
    p = igamc(N / 2.0, chi / 2.0)
    return ("block_frequency", p)

def sp_runs(bits):
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= (2.0 / math.sqrt(n)):
        return ("runs", 0.0)
    vobs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            vobs += 1
    num = abs(vobs - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p = erfc(num / den)
    return ("runs", p)

def sp_longest_run(bits):
    # SP800-22 longest-run-of-ones, block size M=10000 variant simplified to M=128
    n = len(bits)
    M, K = 128, 5
    if n < M:
        return ("longest_run_ones", 1.0)
    N = n // M
    v = [0] * (K + 1)
    # classes for M=128: <=4,5,6,7,8,>=9
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        longest = cur = 0
        for b in block:
            cur = cur + 1 if b else 0
            longest = max(longest, cur)
        if longest <= 4:
            v[0] += 1
        elif longest == 5:
            v[1] += 1
        elif longest == 6:
            v[2] += 1
        elif longest == 7:
            v[3] += 1
        elif longest == 8:
            v[4] += 1
        else:
            v[5] += 1
    pi = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
    chi = sum((v[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(6))
    p = igamc(K / 2.0, chi / 2.0)
    return ("longest_run_ones", p)

def sp_cusum(bits):
    n = len(bits)
    X = [1 if b else -1 for b in bits]
    # forward
    S = 0
    z = 0
    for x in X:
        S += x
        z = max(z, abs(S))
    if z == 0:
        return ("cumulative_sums", 1.0)
    def term_sum():
        total1 = 0.0
        k0 = int(math.floor((-n / z + 1) / 4))
        k1 = int(math.floor((n / z - 1) / 4))
        for k in range(k0, k1 + 1):
            total1 += phi((4 * k + 1) * z / math.sqrt(n)) - phi((4 * k - 1) * z / math.sqrt(n))
        k0 = int(math.floor((-n / z - 3) / 4))
        total2 = 0.0
        for k in range(k0, k1 + 1):
            total2 += phi((4 * k + 3) * z / math.sqrt(n)) - phi((4 * k + 1) * z / math.sqrt(n))
        return total1, total2
    def phi(x):
        return 0.5 * (1 + math.erf(x / math.sqrt(2)))
    t1, t2 = term_sum()
    p = 1.0 - t1 + t2
    p = min(max(p, 0.0), 1.0)
    return ("cumulative_sums", p)

def sp_approx_entropy(bits, m=2):
    n = len(bits)
    def phi(mm):
        if mm == 0:
            return 0.0
        counts = {}
        ext = bits + bits[:mm - 1]
        for i in range(n):
            key = tuple(ext[i:i + mm])
            counts[key] = counts.get(key, 0) + 1
        s = 0.0
        for c in counts.values():
            pr = c / n
            s += pr * math.log(pr)
        return s
    apen = phi(m) - phi(m + 1)
    chi = 2 * n * (math.log(2) - apen)
    p = igamc(2 ** (m - 1), chi / 2.0)
    return ("approximate_entropy", p)

def sp_serial(bits, m=3):
    n = len(bits)
    def psi2(mm):
        if mm == 0:
            return 0.0
        counts = {}
        ext = bits + bits[:mm - 1]
        for i in range(n):
            key = tuple(ext[i:i + mm])
            counts[key] = counts.get(key, 0) + 1
        return (2 ** mm / n) * sum(c * c for c in counts.values()) - n
    p0 = psi2(m)
    p1 = psi2(m - 1)
    p2 = psi2(m - 2)
    d1 = p0 - p1
    d2 = p0 - 2 * p1 + p2
    pv1 = igamc(2 ** (m - 2), d1 / 2.0)
    pv2 = igamc(2 ** (m - 3), d2 / 2.0)
    return [("serial_1", pv1), ("serial_2", pv2)]

def sp_spectral(bits):
    try:
        import numpy as np
    except Exception:
        return ("spectral_dft", None)  # skipped
    n = len(bits)
    X = np.array([1 if b else -1 for b in bits], dtype=float)
    S = np.abs(np.fft.fft(X))[: n // 2]
    T = math.sqrt(math.log(1 / 0.05) * n)
    N0 = 0.95 * n / 2.0
    N1 = float(np.sum(S < T))
    d = (N1 - N0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    p = erfc(abs(d) / math.sqrt(2))
    return ("spectral_dft", p)

def sp80022_battery(data, alpha=0.01):
    bits = bits_from_bytes(data)
    out = []
    out.append(sp_monobit(bits))
    out.append(sp_block_frequency(bits))
    out.append(sp_runs(bits))
    out.append(sp_longest_run(bits))
    out.append(sp_cusum(bits))
    out.append(sp_approx_entropy(bits))
    out.extend(sp_serial(bits))
    out.append(sp_spectral(bits))
    res = []
    for name, p in out:
        if p is None:
            res.append((name, None, "skipped (numpy not available)"))
        else:
            res.append((name, p >= alpha, f"p={p:.4f} (alpha={alpha})"))
    return res

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?", help="input byte file (default stdin)")
    ap.add_argument("--mode", choices=["simple", "sp80022", "both"], default="both")
    ap.add_argument("--alpha", type=float, default=0.01)
    args = ap.parse_args()
    data = open(args.file, "rb").read() if args.file else sys.stdin.buffer.read()
    print(f"# input: {len(data)} bytes ({len(data)*8} bits)\n")
    overall = True
    if args.mode in ("simple", "both"):
        print("== simple FIPS/AIS31-style battery ==")
        for name, ok, detail in simple_battery(data):
            print(f"  [{'PASS' if ok else 'FAIL'}] {name:22s} {detail}")
            overall = overall and ok
        print()
    if args.mode in ("sp80022", "both"):
        print("== NIST SP800-22 subset ==")
        for name, ok, detail in sp80022_battery(data, args.alpha):
            tag = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
            print(f"  [{tag}] {name:22s} {detail}")
            if ok is not None:
                overall = overall and ok
        print()
    print(f"OVERALL: {'ALL TESTS PASS' if overall else 'AT LEAST ONE FAIL'}")
    sys.exit(0 if overall else 1)

if __name__ == "__main__":
    main()
