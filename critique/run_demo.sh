#!/usr/bin/env bash
# run_demo.sh - Section 7.1 demonstration
#
# Shows that a PREDICTABLE stream (AES-256-CTR from a published key) passes the
# same statistical-testing approach ENISA ACM Section 7.1 lists as a way to
# "assess the quality of the output of a random source", with a verdict
# indistinguishable from os.urandom.
#
# Usage:
#   ./run_demo.sh                         # uses bundled predict_streamB_demo.py
#   ./run_demo.sh /path/to/predict_streamB.py   # uses your original generator
set -euo pipefail
cd "$(dirname "$0")"

NBYTES=1250000   # 10,000,000 bits
GEN="${1:-}"

echo "### Generating PREDICTABLE stream (published-key AES-256-CTR) ###"
if [[ -n "$GEN" && -f "$GEN" ]]; then
    python3 "$GEN" fakeB.bin "$NBYTES" 2>/dev/null || python3 "$GEN" > fakeB.bin
else
    python3 predict_streamB_demo.py fakeB.bin "$NBYTES"
fi

echo "### Generating REAL stream (os.urandom) for comparison ###"
python3 - "$NBYTES" <<'PY'
import os,sys
open("real.bin","wb").write(os.urandom(int(sys.argv[1])))
print("wrote real.bin")
PY

echo; echo "############ PREDICTABLE stream (should NOT be trusted) ############"
python3 battery.py fakeB.bin --mode both || true

echo; echo "############ REAL stream (os.urandom) ############"
python3 battery.py real.bin --mode both || true

echo; echo "############ ENISA quantitative thresholds — PREDICTABLE stream ############"
python3 entropy_claim_assessment.py fakeB.bin --public-key --key-bits 256 || true

echo; echo "############ ENISA quantitative thresholds — REAL stream (contrast) ############"
python3 entropy_claim_assessment.py real.bin --key-bits 256 | head -6 || true

echo
echo "Conclusion:"
echo " 1) Both streams receive the SAME statistical verdict; the predictable one is"
echo "    fully reproducible from the published key in predict_streamB_demo.py."
echo " 2) The predictable stream has 0 true secret min-entropy, yet ENISA's entropy"
echo "    thresholds (>=125/>=188) are FALSELY CREDITED by the §7.1 statistical-testing"
echo "    path, and its size thresholds (>=192/>=384) are MET BY CONSTRUCTION."
echo " => Statistical testing cannot serve as a source-quality OR entropy assessment."
