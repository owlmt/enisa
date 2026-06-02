# Host RNG compliance — Windows vs WSL (same laptop)

Side-by-side of the two host RNG stacks on one physical machine (Samsung Galaxy Book,
Intel i7-10510U), assessed against the *architecturally sound* ENISA ACM v2 requirements.
Both columns are from real runs by the operator; see `evidence/`.

- **Windows:** `assess_windows.ps1`, Administrator PowerShell, 2026-06-02.
- **WSL:** `assess_linux.sh`, WSL2 kernel 5.15, 2026-06-02 (`compliance/` + `critique/evidence/`).

> **Reading note.** The verdicts below are *evidence-of-design* (the CNG and Linux RNG
> constructions are publicly documented and, for CNG, CMVP-validated), not
> *evidence-of-implementation* measured on this box. Statistical testing of output is
> deliberately excluded as a criterion (see `../critique/SECTION_7.1_CRITIQUE.md`).

## Platform / hardware (shared — it is one laptop)

| Field | Value |
|-------|-------|
| CPU | Intel Core i7-10510U (4C/8T, 64-bit) |
| RAM | 15.8 GB |
| Machine | Samsung NP950XCJ-X01DE, BIOS AMI P10RFD.058 |
| RDRAND / RDSEED | present (confirmed from Linux `/proc/cpuinfo` flag read: yes/yes) |
| TPM | **2.0 present & ready, manufacturer INTC (Intel PTT firmware TPM)** |
| Windows OS | Windows 11 Home **Insider Preview, build 26220** |
| WSL kernel | 5.15.146.1-microsoft-standard-WSL2 |

## ENISA sound-criteria verdicts

| Criterion (ENISA ACM v2 note) | Windows 11 — CNG | WSL 5.15 — getrandom |
|---|---|---|
| CSPRNG construction | **AES-256 CTR_DRBG** (SP800-90A) | ChaCha20-based DRNG (pre-5.17 random.c) |
| Agreed DRBG = HMAC/Hash/CTR_DRBG (Note D1) | **MEETS** ✓ (CTR_DRBG is on the list) | **DEVIATES** ✗ (ChaCha20 not on the list) |
| TRNG only seeds DRBG (Note 67) | MEETS | MEETS |
| Seed min-entropy ≥125 (Note 68) | MEETS | MEETS |
| Backtracking resistance for PFS (Note 70) | MEETS | MEETS (fast key erasure) |
| Quantum seed ≥188 (Note 69) | CONDITIONAL | CONDITIONAL |
| CTR_DRBG key ≥192 in quantum ctx (Note 71) | MEETS (AES-256) | n/a (not CTR_DRBG) |
| FIPS 140 / formal scheme | CMVP cert exists; **FIPS policy currently disabled** | no formal AIS 20/31 path (default ChaCha20) |
| BSI AIS 20/31 class | n/a (not a Linux kernel) | DRG.3 (kernel 5.6–5.17 range) |
| Source modeling evidence (§7.1 approach 2) | CNG design docs / CMVP | BSI LRNG study |

## The point of the comparison

**Same laptop, same physical entropy sources (RDRAND/RDSEED/TPM), two different ENISA
verdicts** — determined entirely by which RNG stack an application calls:

- **Windows CNG MEETS** the agreed-DRBG requirement because its CSPRNG is an
  AES-256 CTR_DRBG, one of ENISA's three named SP800-90A DRBGs.
- **WSL's default `getrandom` DEVIATES** because its ChaCha20 construction — although
  cryptographically sound and backtracking-resistant — is **not** on ENISA's agreed
  DRBG list.

The two stacks agree on every *principle* (TRNG-seeds-DRBG, ≥125-bit seed, backtracking
resistance) and differ only on the *named-algorithm* requirement. So an application's
ENISA agreed-DRBG posture on this machine depends on its RNG API choice, not on the
hardware beneath it.

## Caveats carried into any report

1. **Windows is an Insider Preview build (26220)** — a pre-release configuration, not a
   released/certifiable baseline. Note this explicitly if the report implies certification.
2. **FIPS policy is disabled** — CMVP-validated algorithms exist in Windows but are not
   being *enforced* in this configuration. "CTR_DRBG on the agreed list" is an
   architecture fact; "running under FIPS-enforced mode" is a separate, currently-unmet
   condition.
3. **RDRAND/RDSEED** on the Windows side is confirmed via the Linux flag read on the same
   CPU, not via a native Windows CPUID probe (the PowerShell script reports it heuristically;
   verify with Sysinternals `coreinfo -f` if a native Windows citation is required).
4. Verdicts are **design-level**, not measurements of this machine's implementation.
