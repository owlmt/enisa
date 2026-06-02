# How to run / reproduce

Everything here is reproducible in a few minutes. Three independent things you can run:
the **§7.1 demonstration** (the predictable-RNG counterexample), the **Linux host
assessment** (WSL or EC2), and the **Windows host assessment** (laptop). None of them
require root except where noted.

---

## Prerequisites

| Task | Needs |
|------|-------|
| §7.1 demo (`critique/run_demo.sh`) | Python 3, `pycryptodome`; `numpy` optional (enables the spectral test) |
| Diagram (`critique/make_diagram.py`) | Python 3, `matplotlib` |
| Linux assessment (`compliance/assess_linux.sh`) | bash + standard coreutils (no extra deps) |
| Windows assessment (`compliance/assess_windows.ps1`) | PowerShell; **Administrator** for TPM/FIPS fields |

Install the Python deps once:

```bash
pip3 install pycryptodome numpy matplotlib --quiet
```

---

## 1. Reproduce the §7.1 demonstration

Shows a fully predictable AES-256-CTR stream (from a **published** key, zero secret
entropy) passing the statistical-testing path identically to `os.urandom`.

```bash
cd critique
./run_demo.sh
```

**What success looks like:**
- `OK: byte-for-byte reproducible.` — the predictable stream matches the pinned
  SHA-256 `ffb11ee80ee4d3ab70f043984c926be88d46836adf6055230656c99077b44e30`.
  This is identical on every machine (it is deterministic).
- Both streams print `OVERALL: ALL TESTS PASS`.
- The predictable stream's output-MCV min-entropy (~0.999 bits/bit) is
  indistinguishable from the real source, while its **true secret min-entropy is 0**.

Note: the **os.urandom** numbers differ on every run — that is correct (a real source is
not reproducible). Only the predictable column reproduces exactly. If `numpy` is absent,
the `spectral_dft` test prints `SKIP`; the other tests still run.

Run a single battery on any file:

```bash
python3 battery.py <file.bin> --mode both        # simple + SP800-22-style subset
python3 entropy_claim_assessment.py <file.bin> --public-key --key-bits 256
```

Regenerate the figure from the committed data:

```bash
python3 make_diagram.py                # uses the recorded WSL run data
python3 make_diagram.py --self-run     # regenerate streams locally, recompute, then plot
```

---

## 2. Linux host assessment (WSL or EC2)

```bash
cd compliance
bash assess_linux.sh
```

Reports CPU/RNG inventory, the BSI AIS 20/31 kernel mapping, and the ENISA sound-criteria
verdicts. **Every verdict line is tagged with its basis:**
`[measured]` (read from this host), `[derived]` (computed from the measured kernel version),
or `[design]` (a documented property of the Linux RNG, *not* verified on this host).
Writes `linux_assessment.json`. No root required (a couple of `dmesg` fields read better
with root).

To run on a remote EC2 instance, the simplest path is to clone this repo on the instance:

```bash
git clone https://github.com/owlmt/enisa.git && cd enisa/compliance && bash assess_linux.sh
```

---

## 3. Windows host assessment (laptop)

Run from **Administrator** PowerShell so the TPM and FIPS-policy fields populate:

```powershell
cd C:\path\to\enisa\compliance
powershell -ExecutionPolicy Bypass -File .\assess_windows.ps1
```

Reports hardware/TPM/FIPS inventory and the CNG ENISA verdicts (each tagged
`[measured]`/`[design]`). Writes `windows_assessment.json`.

---

## What the verdicts mean (important)

These tools assess **architecture/design**, not a black-box statistical battery. A
`[design]` verdict (e.g. "TRNG only seeds DRBG", "seed ≥125 bits") is a documented property
of the platform RNG, **asserted, not measured on your host**. A `[measured]` line (e.g.
`vmgenid=no`, `entropy_avail`) is read live. Statistical testing of output is **deliberately
excluded** as a compliance criterion — see `critique/SECTION_7.1_CRITIQUE.md` for why a
predictable stream passes it. Treat the output as evidence-of-design plus a live inventory,
not as certification.

Generated artifacts (`*.bin`, `*_assessment.json`) are git-ignored; commit only the
evidence logs you intend to publish.
