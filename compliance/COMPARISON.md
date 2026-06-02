# Host RNG compliance — Windows vs WSL vs EC2

Side-by-side of three host RNG stacks assessed against the *architecturally sound*
ENISA ACM v2 requirements. All columns are from real runs by the operator; raw logs
are committed under `compliance/evidence/` and `critique/evidence/`.

| Target | Source | Run |
|--------|--------|-----|
| **Windows 11** (laptop) | `assess_windows.ps1`, Administrator PowerShell | `compliance/evidence/windows_20260602T184306Z.log` |
| **WSL 5.15** (same laptop) | `assess_linux.sh` | `critique/evidence/wsl_20260602T183126Z.log` |
| **AWS EC2** (Nitro, AL2023) | `assess_linux.sh` | `compliance/evidence/ec2_assess_20260602T185603Z.log` |

> **Reading note.** Verdicts are *evidence-of-design* (the CNG and Linux RNG constructions
> are publicly documented and, for CNG, CMVP-validated), not *evidence-of-implementation*
> measured on each box. Statistical testing of output is deliberately excluded as a
> criterion (see `../critique/SECTION_7.1_CRITIQUE.md`).

## Platform / hardware

| Field | Windows 11 (laptop) | WSL 5.15 (same laptop) | AWS EC2 t3.micro |
|-------|---------------------|------------------------|------------------|
| CPU | Intel i7-10510U (4C/8T) | Intel i7-10510U (4C/8T) | Intel Xeon Platinum 8259CL (2 vCPU) |
| RAM | 15.8 GB | 15.8 GB | 916 MB |
| RDRAND / RDSEED | present¹ | yes / yes | yes / yes |
| TPM | **2.0 present, Intel PTT (INTC)** | n/a (passthrough) | none exposed |
| OS / kernel | Win 11 Home **Insider Preview 26220** | 5.15.146.1-microsoft-WSL2 | 6.1.172 amzn2023 |
| Virtualization | Hyper-V present | WSL2 lightweight VM | **Nitro (detected: EC2=yes, virt=amazon)** |

¹ Windows RDRAND/RDSEED reported heuristically by the script; confirmed via the Linux
`/proc/cpuinfo` flag read on the same CPU (yes/yes).

## ENISA sound-criteria verdicts

| Criterion (ENISA ACM v2 note) | Windows 11 — CNG | WSL 5.15 — getrandom | EC2 — getrandom |
|---|---|---|---|
| CSPRNG construction | **AES-256 CTR_DRBG** (SP800-90A) | ChaCha20 DRNG (pre-5.17) | ChaCha20 DRNG + BLAKE2s pool + fast key erasure |
| Agreed DRBG = HMAC/Hash/CTR_DRBG (Note D1) | **MEETS** ✓ | **DEVIATES** ✗ | **DEVIATES** ✗ |
| TRNG only seeds DRBG (Note 67) | MEETS | MEETS | MEETS |
| Seed min-entropy ≥125 (Note 68) | MEETS | MEETS | MEETS |
| Backtracking resistance for PFS (Note 70) | MEETS | MEETS | MEETS |
| Quantum seed ≥188 (Note 69) | CONDITIONAL | CONDITIONAL | CONDITIONAL |
| CTR_DRBG key ≥192 in quantum ctx (Note 71) | MEETS (AES-256) | n/a | n/a |
| FIPS 140 / formal scheme | CMVP cert exists; **FIPS policy disabled** | no formal AIS 20/31 path | no formal AIS 20/31 path |
| BSI AIS 20/31 class | n/a (not a Linux kernel) | DRG.3 (5.6–5.17) | **NONE** (kernel 6.1; DRT.1.4 unmet) |
| Source modeling evidence (§7.1 approach 2) | CNG design docs / CMVP | BSI LRNG study | BSI LRNG study |

## VM-specific findings (EC2 only)

These could not be exercised on WSL (a lightweight VM that hides most of the surface) or
on Windows; they appear only on real virtualized cloud infrastructure:

| Check | EC2 result | Implication |
|-------|------------|-------------|
| EC2 / Nitro detection | **yes** (sys_vendor/virt=amazon) | the assessment correctly identifies the cloud VM context |
| `vmgenid` driver | **no** | **VM-RISK:** no kernel-level guard against RNG-state duplication if the instance is cloned/snapshotted (the BSI "Randomness in VMs" failure mode) |
| `hwrng` / `virtio-rng` passthrough | **none** | no hardware RNG exposed to the guest; the RNG leans on RDRAND/RDSEED + jitterentropy |
| `jitterentropy_rng` | **yes** | software entropy source present (CPU execution-timing jitter) |
| boot-time `crng init done` | unknown (needs root dmesg) | boot-time entropy timing not captured at this privilege; BSI VM study flags this as reduced under virtualization |

## The point of the comparison

**Three machines, three different postures — driven by the RNG stack, not the hardware:**

- **Windows CNG MEETS** the agreed-DRBG requirement (AES-256 CTR_DRBG is one of ENISA's
  three named SP800-90A DRBGs).
- **WSL and EC2 both DEVIATE** — their ChaCha20 `getrandom` construction, though sound and
  backtracking-resistant, is **not** on ENISA's agreed DRBG list. They agree on every
  *principle* (TRNG-seeds-DRBG, ≥125-bit seed, backtracking resistance) and differ only on
  the *named-algorithm* requirement.
- **EC2 is the weakest formal posture:** kernel 6.1 has **no formal AIS 20/31 class** at all
  (DRT.1.4 request-length requirement unmet — not a cryptographic weakness), *and* it carries
  live VM-specific risk (no `vmgenid`, no hwrng passthrough) that the others don't surface.

So an application's ENISA agreed-DRBG posture depends on which RNG API it calls and where it
runs — not on the silicon beneath it (all three have RDRAND/RDSEED).

## Cross-platform reproducibility of the §7.1 counterexample

The predictable AES-256-CTR stream (published key) produced a **byte-identical SHA-256**
`ffb11ee80ee4d3ab70f043984c926be88d46836adf6055230656c99077b44e30` on all three machines
(Windows/WSL via the same generator, EC2 verified in `critique/evidence/ec2_demo_*.log`),
across three different CPUs and OSes — confirming the demonstration is platform-independent:
a zero-entropy generator passes the statistical-testing path identically everywhere.

## Caveats carried into any report

1. **Windows is an Insider Preview build (26220)** — pre-release, not a certifiable baseline.
2. **Windows FIPS policy is disabled** — CMVP-validated algorithms exist but are not enforced.
3. **RDRAND/RDSEED** on Windows confirmed via the Linux flag read on the same CPU, not a native
   Windows CPUID probe.
4. Verdicts are **design-level**, not measurements of each machine's implementation.
5. The EC2 `spectral_dft` test was skipped in the demo log (numpy absent on the instance);
   the other 8 SP800-22-style tests ran and passed. Install numpy for full parity if needed.
