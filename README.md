# Entropy & Randomness Requirements — ENISA / ECCG *Agreed Cryptographic Mechanisms*

A consolidated, traceable list of every entropy-, randomness-, and RNG-related requirement in the ENISA EUCC guideline on cryptography, as an aid for developers and evaluators working on RNG/DRBG assurance.

## Repository contents

This repository has three parts:

1. **`README.md` (this file) — the requirements list.** Every entropy/randomness/RNG requirement in the ENISA ACM, keyed to section and note numbers of the published v2.0.

2. **`compliance/` — host RNG posture assessment.** Scripts and methodology to assess a Windows laptop (PowerShell), WSL, and an AWS EC2 VM against the *architecturally sound* requirements only (statistical testing is deliberately excluded as a compliance criterion — see below). Start with `compliance/METHODOLOGY.md`, then run `assess_windows.ps1` or `assess_linux.sh`.

3. **`critique/` — why §7.1's statistical-testing path is unsound.** A reproducible demonstration that a fully *predictable* generator (AES-256-CTR keystream from a **published** key, zero secret entropy) passes the statistical-testing approach that ENISA ACM §7.1 lists for assessing a random source, and is even *credited* with meeting ENISA's quantitative min-entropy thresholds. Includes a ready-to-file ECCG ACM update submission. Start with `critique/SECTION_7.1_CRITIQUE.md`; run `critique/run_demo.sh` to reproduce.

The throughline: ENISA's randomness requirements are **architectural/design** requirements on the RNG→DRBG construction, not a black-box statistical battery one "passes." `compliance/` assesses against the sound requirements; `critique/` proves why the statistical-testing requirement in §7.1 must be demoted to runtime failure-detection only.

## Source & version

- **Authoritative document:** ECCG Sub-group on Cryptography, *Agreed Cryptographic Mechanisms*, **Version 2.0, April 2025** (published 6 May 2025).
- **Publication page:** https://certification.enisa.europa.eu/publications/eucc-guidelines-cryptography_en
- **Direct PDF:** *ECCG Agreed Cryptographic Mechanisms version 2* / *EUCC Guidelines Cryptography v2*.

> **Version note.** All section and note numbers below are to the **published v2.0 (April 2025)**. References are given at section/note granularity rather than page numbers, since pagination is not stable across renders; verify each against your copy of v2.0. A later **Working Draft dated April 2026** also exists; it renumbers most notes, relabels "legacy → admissible", and adds mechanisms not in v2.0 (Argon2-id with a 128-bit salt, SP800-227 KEM combiners, EdDSA, SHAKE/cSHAKE XOFs). A draft↔v2.0 note-number map is given at the end so requirements stay citable against whichever version a reader holds. **When citing ENISA, cite v2.0** unless the draft has since been published.

---

## 1. Foundational / definitional

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| F1 | "Key length" denotes the **entropy of the key-generation mechanism**, not the storage size (DES = 56 not 64 bits; 3-key TDES = 168 not 192). | §1.3 |
| F2 | For asymmetric keys, the generation method **must not be exploitable towards a speedup** of the best attack vs. uniform random generation; and the **entropy of asymmetric keys ≥ acceptable symmetric key length**. Applies to RSA, FF-DH, EC-DH/(EC)DSA per-signature values, ML-KEM, ML-DSA, and PQC ephemerals. | §1.3 |
| F3 | Keys must be **unpredictable**, long enough, and the generator's **output distribution must be indistinguishable from uniform** to an adversary. | §8.1 |

---

## 2. True Random Source (§7.1)

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| T1 | Source quality may be assessed by **statistical testing** — black-box, no source knowledge needed; detects only specific defects, gives **no assurance on the output distribution**, and is mainly useful to catch unintentional failure. | §7.1 |
| T2 | Or by **source modeling** — requires deep understanding of the source design plus physics/statistics expertise; gives **better assurance**. (Preferred, with the caveat that model-vs-reality correspondence is hard to evaluate.) | §7.1 |
| T3 | **Note 67-NoDirectRandomSource:** a true random source's output should be used **only as (re)seed material or additional input to a DRBG**. **Direct use of a pure TRNG is *not agreed*.** | §7.1 |

---

## 3. Deterministic Random Bit Generator (§7.2)

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| D1 | Agreed DRBGs: **HMAC_DRBG, Hash_DRBG, CTR_DRBG** (all R; CTR_DRBG carries Note 71). | §7.2 |
| D2 | **Note 68-DRG-Seeding:** the DRG's security derives from proper seeding; the **min-entropy mandated by the DRG's own spec shall be respected**, and the **seed min-entropy shall be ≥125 bits**. | §7.2 |
| D3 | **Note 69-Quantum-Threat:** in quantum-resistant contexts, **seed min-entropy ≥188 bits** recommended. | §7.2 |
| D4 | **Note 70-BacktrackingResistance:** systems providing PFS must use a DRG from whose **current state past outputs cannot be practically computed** (backward / backtracking resistance). | §7.2 |
| D5 | **Note 71-QuantumThreat:** in quantum-resistant contexts, **do not use CTR_DRBG with a block-cipher key < 192 bits**. | §7.2 |

---

## 4. RNG with Specific Distribution (§7.3)

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| S1 | For uniform integers in [0, q−1] with q not a power of 2: **"Testing" technique** (FIPS 186-5 App. B.1.2) R, and **"Extra-random" technique** (FIPS 186-5 App. B.1.1) R. | §7.3 |
| S2 | **Note 72-RandomModularReduction:** the naive "draw 2^ℓ then reduce mod q" method **introduces exploitable bias** — not agreed on its own. Testing = uniform at the cost of variable extra randomness; Extra-random = negligible bias at fixed small extra randomness. | §7.3 |
| S3 | Agreed prime-generation methods (rejection sampling Method 1/2, auxiliary primes FIPS 186-5 App. C.9) — all R; none vulnerable to ROCA. | §7.3 |
| S4 | **Note 73-ProbablePrime:** if primality is not proven, the **probability the candidate is composite must be < 2⁻¹²⁵** (Miller-Rabin iteration counts in Table 2; each iteration on a randomly selected basis). | §7.3 |
| S5 | **Note 74-RSAKeyGen:** RSA primes p, q are **randomly generated**, equal length, with **\|p − q\| ≥ 2^(n/2−100)** to resist close-factor attacks. | §7.3 |

---

## 5. IV / Nonce / Keystream

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| I1 | **Note 5-IVType:** an encryption scheme must be **probabilistic with a random IV**, or use a **nonce** (one-time per key). **Constant or predictable IVs are not accepted.** | §3.1 |
| I2 | **Note 7-StreamMode:** for stream modes (CTR, OFB), **no two keystreams may ever overlap** — deterministic in CTR; probabilistic in OFB provided the IV-key pair is never reused. | §3.1 |
| I3 | **Note 9-DiskEncStreamMode:** disk-encryption IVs are deterministic (derived from storage location); stream modes are therefore improper there. | §3.2 |
| I4 | **Note 22-GMAC-GCMNonce:** the IV must be managed inside the AE security perimeter; **no adversary may cause IV reuse** for different (plaintext, AD) pairs under one key. | §3.5 |
| I5 | **Note 23-GMAC-GCMOptions:** the only agreed GCM config is **96-bit IV + deterministic IV construction (SP 800-38D §8.2.1) + 128-bit tag**. | §3.5 |

---

## 6. Disk-encryption tweak / sector uniqueness (§3.2)

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| K1 | **Note 10-UniqueTweak:** each block-position tweak value shall be **unique** under a given key. | §3.2 |
| K2 | **Note 11-AddressTweak:** logical-address-derived tweaks need extra conformance checks. | §3.2 |
| K3 | **Note 12-UniqueSectorNumber:** each sector shall have a **unique sector number** under a given key. | §3.2 |
| K4 | **Note 13-AddressSectorNumber:** logical-address-derived sector numbers need extra conformance checks. | §3.2 |

---

## 7. Challenge randomness (entity authentication)

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| C1 | **Note 20-CollChallenge:** a challenge must **not be replayable with non-negligible probability**; implement as a random value, large enough, generated by the verifier. | §3.4 |
| C2 | Agreed challenge sizes: **ℓ ≥ 125 bits = R**; **96 ≤ ℓ < 125 bits = L (legacy)**. | §3.4 |

---

## 8. Salt & KDF entropy

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| P1 | **Note 28-Salt:** a salt is a **random** value, **generated at password registration**, stored with the verifier; **length ≥ 128 bits**. | §3.8 |
| P2 | **Note 26-PBKDF2-PRF:** if the HMAC key exceeds the hash block length it is prehashed, which can **lower the effective entropy** of the PBKDF2-derived key. | §3.7 |

> *Draft-only:* the April 2026 draft adds Argon2-id with an agreed parameter set that also fixes a **128-bit salt** (Note 27-Argon Parameters). Not present in v2.0.

---

## 9. Padding & signature randomness

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| R1 | **Note 42-RandomPadding:** asymmetric encryption (RSA-OAEP, PKCS#1v1.5) randomized padding **shall be generated by an agreed random bit generator** (per §7). | §5.1 |
| R2 | **Note 49-DSARandom:** for DSA/ECDSA/Schnorr per-signature random values, **leakage or RNG bias endangers the long-term key** (both statistical bias *and* per-bit side-channel leakage). Recommendation: use a **strong RNG with strong cryptographic post-processing, enhanced backward security, and regular reseeding from a true random source**. | §5.2 |

> *Draft-only:* the April 2026 draft adds EdDSA with **Note 51-DeterministicSignatures** — its per-signature value is derived **pseudo-randomly from secret key + message** (no RNG needed) but is fault-attack susceptible. Not present in v2.0.

---

## 10. Key-generation seed entropy (§8.1)

| # | Requirement | Ref (v2.0) |
|---|-------------|-----------|
| G1 | Agreed key-generation methods: **agreed RBG**, **agreed key-establishment mechanism**, **agreed KDF**; keys obtained by truncating the generator output to the key size. | §8.1 |
| G2 | **Note 77-KeyEstablishment:** a key from key establishment **shall not be used directly** — first post-processed by an agreed KDF. | §8.1 |
| G3 | **Note 78-KeyGenerationSeed:** the **entropy of preexisting secrets shall be ≥125 bits** — explicitly including **Diffie-Hellman ephemeral exponents** and the **TLS Record Protocol master secret**. | §8.1 |

---

## 11. PQC / quantum thresholds affecting randomness

| Item | Recommendation (quantum-resistant contexts) | Ref (v2.0) |
|------|---------------------------------------------|-----------|
| DRBG seed min-entropy | **≥188 bits** | Note 69 |
| CTR_DRBG block-cipher key | **≥192 bits** | Note 71 |
| Symmetric keys / block ciphers | **≥192 bits** | Notes 3 / 19 |
| Hash output | **≥384 bits** | Note 4 |
| MAC keys (hash-based) | **≥192 bits** | Note 19 |

---

## What ENISA deliberately does *not* specify

The guideline **delegates detailed entropy-estimation methodology** to external standards (AIS 31, ISO/IEC 20543, NIST SP 800-90B). It does **not** prescribe SP 800-90B estimators, MultiMMC, LZ78Y, compression estimators, restart tests, IID / non-IID procedures, AIS 31 PTG.2 entropy formulas, or any explicit entropy-accounting method. Its randomness assurance rests on three pillars only: **(1)** statistical testing, **(2)** source modeling (preferred), and **(3)** min-entropy claims for seeding.

---

## The five strongest entropy positions (summary)

1. **Key strength = entropy of the generator, not nominal bit size** (F1).
2. **Asymmetric key entropy ≥ acceptable symmetric key length** (F2).
3. **TRNGs may only seed DRBGs — never be used directly** (Note 67).
4. **DRBG seed min-entropy ≥125 bits (≥188 bits in quantum contexts)** (Notes 68 / 69).
5. **Source modeling is preferred over statistical testing alone** (T1 / T2).

---

## Appendix — Note-number map (April 2026 draft ↔ published v2.0)

| Topic | April 2026 draft | **Published v2.0** |
|-------|------------------|--------------------|
| IVType | Note 5 | Note 5 |
| StreamMode | Note 7 | Note 7 |
| DiskEncStreamMode | Note 9 | Note 9 |
| UniqueTweak … AddressSectorNumber | Notes 10–13 | Notes 10–13 |
| CollChallenge | Note 20 | Note 20 |
| GMAC-GCMNonce | Note 22 | Note 22 |
| GMAC-GCMOptions | Note 23 | Note 23 |
| PBKDF2-PRF (entropy) | Note 26 | Note 26 |
| Salt ≥128 bits | Note 29 | **Note 28** |
| RandomPadding from agreed RBG | Note 43 | **Note 42** |
| DSARandom | Note 50 | **Note 49** |
| NoDirectRandomSource | Note 70 | **Note 67** |
| DRG-Seeding ≥125 | Note 71 | **Note 68** |
| Quantum seed ≥188 | Note 72 | **Note 69** |
| BacktrackingResistance | Note 73 | **Note 70** |
| CTR_DRBG quantum key ≥192 | Note 74 | **Note 71** |
| RandomModularReduction | Note 75 | **Note 72** |
| ProbablePrime <2⁻¹²⁵ | Note 76 | **Note 73** |
| RSAKeyGen \|p−q\| bound | Note 77 | **Note 74** |
| KeyEstablishment (post-process) | Note 80 | **Note 77** |
| KeyGenerationSeed ≥125 | Note 81 | **Note 78** |
| Argon2 128-bit salt | Note 27 | *(not in v2.0)* |
| EdDSA DeterministicSignatures | Note 51 | *(not in v2.0)* |
