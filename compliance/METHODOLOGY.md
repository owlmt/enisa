# Compliance methodology — assessing a host RNG against ENISA ACM (sound criteria only)

This folder assesses the random-generation posture of three targets — a Windows
laptop (PowerShell), WSL, and an AWS EC2 VM — against the **architecturally sound**
randomness requirements of ENISA ACM (see `../README.md`, keyed to published v2.0).

## Ground rule: statistical testing is NOT a compliance criterion

Per `../critique/SECTION_7.1_CRITIQUE.md`, statistical testing of output cannot
establish source quality (a published-key keystream passes it). It is therefore
**excluded as a compliance criterion here** and used only — if at all — as a
runtime failure-detection signal. Compliance is judged on the **design/architecture**
of the RNG–DRBG construction and its configuration.

## Applicability matrix

| ENISA requirement (v2.0 note) | Host-RNG relevant? | How assessed |
|---|---|---|
| TRNG only seeds a DRBG; no direct TRNG use (Note 67) | **Yes** | Architecture: does the user-facing API expose only DRBG output? |
| Agreed DRBG = HMAC/Hash/CTR_DRBG, SP800-90A (Note D1) | **Yes** | Identify the OS CSPRNG algorithm; is it on ENISA's agreed list? |
| Seed min-entropy ≥125 bits (Note 68) | **Yes** | Seeding policy / fully-seeded threshold |
| Quantum seed ≥188 bits (Note 69) | Conditional | Only if quantum-resistant posture is claimed |
| Backtracking resistance for PFS (Note 70) | **Yes** | Does state compromise reveal past output? |
| CTR_DRBG block-cipher key ≥192 in quantum contexts (Note 71) | Conditional | Only if CTR_DRBG + quantum posture |
| Source modeling preferred (§7.1 approach 2) | **Yes (evidence)** | Is a published stochastic model available for the source? |
| Preexisting-secret entropy ≥125 (DH exponents, TLS master) (Note 78) | App-level | Out of host-RNG scope; flagged for app audits |
| IV/nonce uniqueness, GCM options, tweak/sector uniqueness, salt ≥128, challenge size, key-usage separation, RSA \|p−q\| bound | App-level | **N/A to a host RNG**; these are application/library obligations |
| Mod-q unbiased sampling (Note 72) | Library-level | N/A to host; relevant to the crypto library, not the OS RNG |

"App-level / library-level" items are reported as **N/A (out of scope)** for a host
posture check — they are properties of how a given application uses crypto, not of
the platform RNG.

## What each script reports

`assess_windows.ps1` and `assess_linux.sh` each emit:

1. **Hardware & platform inventory** — CPU, core/thread count, RDRAND/RDSEED support,
   TPM presence/version, memory, board/BIOS/serial (for the purchase-record section),
   OS build, virtualization status.
2. **RNG architecture findings** mapped to the Yes/Conditional rows above, each marked
   **MEETS / DEVIATES / CONDITIONAL / EVIDENCE-NEEDED**.
3. A **raw sample** (`*_rng_sample.bin`) you can optionally feed to
   `../critique/battery.py` — but only as a failure-detection sanity check, never as
   evidence of compliance.

## Expected high-level findings (summary, verify per host)

- **Windows (CNG / BCryptGenRandom / ProcessPrng):** the CSPRNG is an **AES-256
  CTR_DRBG (SP800-90A)** — i.e. **on ENISA's agreed DRBG list** (Note 71 quantum
  key-size satisfied at 256). FIPS 140 CMVP-validated builds exist; reseeds from
  RDRAND/RDSEED/TPM/interrupt timing; provides backtracking resistance. Strong
  alignment on the sound criteria.
- **Linux (WSL / EC2 — `getrandom`/`/dev/urandom`):** the user-facing CSPRNG is a
  **ChaCha20 DRNG**, which is **not** among ENISA's three agreed SP800-90A DRBGs —
  report as a **DEVIATION** on the DRBG-algorithm requirement, even though it meets
  backtracking resistance (fast key erasure), the ≥125-bit seed (256 bits collected
  before fully-seeded), and TRNG-only-seeds-DRBG. Per the BSI kernel table
  (Dec 2025): kernels **4.9–5.5 → NTG.1**, **5.6–5.17 → DRG.3**, **≥5.18 → no formal
  AIS 20/31 compliance** (request-length requirement DRT.1.4 unmet — *not* a
  cryptographic weakness). For an ENISA agreed-DRBG posture, use a SP800-90A DRBG
  (kernel `drbg` module / jitterentropy, or a userspace SP800-90A DRBG) seeded from
  the kernel.
- **EC2 (adds VM concerns, per BSI "Randomness in VMs"):** snapshot/clone state reuse
  (mitigated since 5.18 by `add_vmfork_randomness` + ACPI VMGENID), reduced boot-time
  entropy, and dependence on `virtio-rng`/hardware RNG passthrough. The scripts flag
  Nitro detection, vmgenid/vmfork support, and hwrng presence.
