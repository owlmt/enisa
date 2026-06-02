#!/usr/bin/env bash
# run_demo.sh - Section 7.1 demonstration (audit-hardened).
#
# Shows that a PREDICTABLE stream (AES-256-CTR from a published key) passes the
# statistical-testing approach ENISA ACM Section 7.1 lists for assessing a random
# source, with a verdict indistinguishable from os.urandom -- while carrying zero
# secret entropy.
#
# Audit hardening:
#   * the predictable stream is verified against a pinned SHA-256 (byte-for-byte
#     reproducibility is part of the claim, so it is checked, not assumed);
#   * the predictable battery runs WITHOUT "|| true" -- if it does not pass, or the
#     hash does not match, the script FAILS. We do not hide failures.
set -euo pipefail
cd "$(dirname "$0")"

NBYTES=1250000   # 10,000,000 bits
GEN="${1:-}"
# Pinned digest of the predictable stream from predict_streamB_demo.py (published
# key 0011..eeff, nonce 000..0, 1,250,000 bytes). Regenerate/verify with:
#   python3 predict_streamB_demo.py fakeB.bin 1250000 && sha256sum fakeB.bin
EXPECTED_SHA256="ffb11ee80ee4d3ab70f043984c926be88d46836adf6055230656c99077b44e30"

echo "### Generating PREDICTABLE stream (published-key AES-256-CTR) ###"
if [[ -n "$GEN" && -f "$GEN" ]]; then
    python3 "$GEN" fakeB.bin "$NBYTES"
else
    python3 predict_streamB_demo.py fakeB.bin "$NBYTES"
fi

echo "### Verifying reproducibility against pinned SHA-256 ###"
ACTUAL_SHA256="$(sha256sum fakeB.bin | awk '{print $1}')"
echo "  expected: $EXPECTED_SHA256"
echo "  actual  : $ACTUAL_SHA256"
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
    echo "FATAL: predictable stream does not match pinned digest. Aborting." >&2
    exit 2
fi
echo "  OK: byte-for-byte reproducible."

echo "### Generating REAL stream (os.urandom) for comparison ###"
python3 - "$NBYTES" <<'PY'
import os,sys
open("real.bin","wb").write(os.urandom(int(sys.argv[1])))
print("wrote real.bin")
PY

echo; echo "############ PREDICTABLE stream (should NOT be trusted) ############"
# No "|| true": a FAIL here must fail the script (set -e). We never hide it.
python3 battery.py fakeB.bin --mode both

echo; echo "############ REAL stream (os.urandom) ############"
# os.urandom may legitimately fail a single test ~alpha of the time; do not abort.
python3 battery.py real.bin --mode both || echo "(note: a real source may trip one test by chance at alpha; verdict above is informational)"

echo; echo "############ ENISA quantitative thresholds — PREDICTABLE stream ############"
python3 entropy_claim_assessment.py fakeB.bin --public-key --key-bits 256

echo; echo "############ ENISA quantitative thresholds — REAL stream (contrast) ############"
python3 entropy_claim_assessment.py real.bin --key-bits 256 2>/dev/null | sed -n '1,6p'

echo
cat <<'TXT'
Conclusion:
 1) Both streams receive the SAME statistical verdict; the predictable one is
    reproducible byte-for-byte (verified against the pinned SHA-256 above).
 2) The predictable stream has 0 true secret min-entropy, yet ENISA's entropy
    thresholds (>=125/>=188) are FALSELY CREDITED by the §7.1 statistical-testing
    path, while its size thresholds (>=192/>=384) are MET BY CONSTRUCTION.
 => Statistical testing of output cannot serve as a source-quality OR entropy
    assessment. It can serve only as a startup/online failure-detection test.
TXT
