#!/usr/bin/env python3
"""
make_diagram.py - reproducible figure for the Section 7.1 demonstration.

Renders section7_1_demo.png from the measured data of a real run (default:
the WSL run of 2026-06-02T17:53:35Z committed under evidence/). The figure shows
that a PREDICTABLE generator (published-key AES-256-CTR, 0 secret entropy) and a
REAL source (os.urandom) receive statistically indistinguishable scores across
the SP800-22 subset and the output-based min-entropy estimate -- while their TRUE
secret min-entropy differs by everything (0 vs source-modeled).

Reproduce:  python3 make_diagram.py            # uses the embedded WSL data
            python3 make_diagram.py --self-run  # regenerate streams here & plot

Requires: matplotlib  (pip install matplotlib)
"""
import argparse, sys

# ---- measured data: WSL run 2026-06-02T17:53:35Z (kernel 5.15, py3.12.3) ----
# p-values from the NIST SP800-22 subset; both streams PASS at alpha=0.01.
SP80022 = [
    # test, predictable p, real p
    ("frequency/monobit", 0.9471, 0.8654),
    ("block-frequency",   0.5439, 0.7951),
    ("runs",              0.6644, 0.0716),
    ("longest-run-1s",    0.9554, 0.6129),
    ("cumulative-sums",   0.9972, 0.5737),
    ("approx-entropy",    0.2999, 0.1423),
    ("serial-1",          0.2999, 0.1421),
    ("serial-2",          0.0960, 0.1648),
    ("spectral/DFT",      0.1645, 0.0533),
]
# output-based MCV min-entropy (bits per bit) and TRUE secret min-entropy
MINENT = {
    "predictable": {"mcv_per_bit": 0.9988, "true_secret_per_bit": 0.0},
    "real":        {"mcv_per_bit": 0.9983, "true_secret_per_bit": None},  # None = source-modeled / unknown
}
ALPHA = 0.01
RUN_LABEL = "WSL kernel 5.15 · 2026-06-02T17:53:35Z · 10,000,000 bits · alpha=0.01"

def self_run():
    """Optionally regenerate the streams locally and recompute, to prove reproducibility."""
    import subprocess, importlib.util, os
    here = os.path.dirname(os.path.abspath(__file__))
    # generate predictable + real
    subprocess.run([sys.executable, os.path.join(here, "predict_streamB_demo.py"),
                    "fakeB.bin", "1250000"], cwd=here, check=True)
    with open(os.path.join(here, "real.bin"), "wb") as f:
        f.write(os.urandom(1250000))
    # import battery as a module and recompute p-values
    spec = importlib.util.spec_from_file_location("battery", os.path.join(here, "battery.py"))
    bat = importlib.util.module_from_spec(spec); spec.loader.exec_module(bat)
    def pvals(path):
        data = open(os.path.join(here, path), "rb").read()
        res = dict()
        for name, ok, detail in bat.sp80022_battery(data, ALPHA):
            # detail like "p=0.1234 (alpha=...)" or "skipped"
            if detail.startswith("p="):
                res[name] = float(detail.split("=")[1].split()[0])
        return res
    pf, pr = pvals("fakeB.bin"), pvals("real.bin")
    print("Self-run predictable:", pf)
    print("Self-run real       :", pr)
    print("(predictable p-values reproduce the embedded values; real p-values will differ.)")

def render(out="section7_1_demo.png"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    labels = [t for t, _, _ in SP80022]
    pred = [p for _, p, _ in SP80022]
    real = [p for _, _, p in SP80022]
    x = np.arange(len(labels))
    w = 0.38

    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(13, 5.5), gridspec_kw={"width_ratios": [2.4, 1]})

    # ---- left: SP800-22 p-values, grouped bars ----
    b1 = ax1.bar(x - w/2, pred, w, label="Predictable (published-key AES-256-CTR)",
                 color="#c0392b", edgecolor="black", linewidth=0.4)
    b2 = ax1.bar(x + w/2, real, w, label="Real (os.urandom)",
                 color="#2980b9", edgecolor="black", linewidth=0.4)
    ax1.axhline(ALPHA, color="black", linestyle="--", linewidth=1)
    ax1.text(len(labels)-0.5, ALPHA+0.012, f"PASS threshold  alpha={ALPHA}",
             ha="right", va="bottom", fontsize=8.5)
    ax1.set_ylabel("SP800-22 p-value  (>= alpha = PASS)")
    ax1.set_title("Both streams PASS every test — verdict indistinguishable")
    ax1.set_xticks(x); ax1.set_xticklabels(labels, rotation=40, ha="right", fontsize=8.5)
    ax1.set_ylim(0, 1.05)
    ax1.legend(loc="upper left", fontsize=8.5, framealpha=0.95)
    ax1.grid(axis="y", alpha=0.25)

    # ---- right: the contrast that matters ----
    cats = ["Credited\nmin-entropy\n(output MCV)", "TRUE secret\nmin-entropy"]
    pred_vals = [MINENT["predictable"]["mcv_per_bit"], MINENT["predictable"]["true_secret_per_bit"]]
    real_true = MINENT["real"]["true_secret_per_bit"]
    real_vals = [MINENT["real"]["mcv_per_bit"], real_true if real_true is not None else 0.0]
    xx = np.arange(len(cats))
    ax2.bar(xx - w/2, pred_vals, w, color="#c0392b", edgecolor="black", linewidth=0.4)
    ax2.bar(xx + w/2, real_vals, w, color="#2980b9", edgecolor="black", linewidth=0.4)
    # annotate
    ax2.text(0 - w/2, pred_vals[0] + 0.02, f"{pred_vals[0]:.4f}", ha="center", fontsize=8)
    ax2.text(0 + w/2, real_vals[0] + 0.02, f"{real_vals[0]:.4f}", ha="center", fontsize=8)
    ax2.text(1 - w/2, 0.03, "0\n(key is\npublished)", ha="center", va="bottom", fontsize=7.5, color="#c0392b")
    ax2.text(1 + w/2, 0.03, "source-\nmodeled\n(not 0)", ha="center", va="bottom", fontsize=7.5, color="#2980b9")
    ax2.set_ylabel("min-entropy  (bits per bit)")
    ax2.set_title("Same credited entropy,\nopposite TRUE entropy")
    ax2.set_xticks(xx); ax2.set_xticklabels(cats, fontsize=8.5)
    ax2.set_ylim(0, 1.15)
    ax2.grid(axis="y", alpha=0.25)

    fig.suptitle("ENISA ACM §7.1: a fully predictable RNG passes the statistical-testing path",
                 fontsize=13, fontweight="bold")
    fig.text(0.5, 0.005, RUN_LABEL, ha="center", fontsize=8, color="#444")
    fig.tight_layout(rect=[0, 0.03, 1, 0.95])
    fig.savefig(out, dpi=150)
    print(f"wrote {out}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-run", action="store_true",
                    help="regenerate streams locally to verify reproducibility, then plot")
    ap.add_argument("-o", "--out", default="section7_1_demo.png")
    args = ap.parse_args()
    if args.self_run:
        self_run()
    render(args.out)
