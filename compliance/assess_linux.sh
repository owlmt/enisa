#!/usr/bin/env bash
# assess_linux.sh — ENISA ACM host RNG posture for WSL and AWS EC2.
# Sound criteria only (statistical testing is NOT used as a compliance criterion).
#
# Run:   bash assess_linux.sh
# Outputs:
#   linux_assessment.json     machine-readable findings + inventory
#   linux_rng_sample.bin      10,000,000 bits from /dev/urandom
#                             (optional failure-detection sanity check only)

set -u
J() { printf '%s' "$1" | sed 's/"/\\"/g'; }   # json-escape
say() { printf '%s\n' "$*"; }
hdr() { printf '\n=== %s ===\n' "$*"; }

# ---------- 1. Platform & virtualization ----------
hdr "Platform & virtualization"
KREL="$(uname -r)"; KMAJ="${KREL%%.*}"; REST="${KREL#*.}"; KMIN="${REST%%.*}"
say "Kernel            : $KREL"
VIRT="$(systemd-detect-virt 2>/dev/null || echo unknown)"
say "Virtualization    : $VIRT"
IS_WSL=no; grep -qiE "microsoft|wsl" /proc/version 2>/dev/null && IS_WSL=yes
say "WSL               : $IS_WSL"
# EC2 / Nitro detection
EC2=no
if [ -r /sys/devices/virtual/dmi/id/sys_vendor ]; then
  grep -qi "amazon" /sys/devices/virtual/dmi/id/sys_vendor 2>/dev/null && EC2=yes
fi
[ -r /sys/hypervisor/uuid ] && grep -qi "^ec2" /sys/hypervisor/uuid 2>/dev/null && EC2=yes
say "AWS EC2           : $EC2"

# ---------- 2. Hardware inventory ----------
hdr "Hardware inventory"
CPU="$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
CORES="$(nproc 2>/dev/null)"
say "CPU               : $CPU"
say "Logical CPUs      : $CORES"
RDRAND=no; grep -qm1 ' rdrand' /proc/cpuinfo && RDRAND=yes
RDSEED=no; grep -qm1 ' rdseed' /proc/cpuinfo && RDSEED=yes
say "RDRAND / RDSEED   : $RDRAND / $RDSEED"
MEMKB="$(grep -m1 MemTotal /proc/meminfo | awk '{print $2}')"
say "MemTotal          : $((MEMKB/1024)) MB"
if [ -r /sys/devices/virtual/dmi/id/product_name ]; then
  say "DMI product       : $(cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null)"
fi

# ---------- 3. RNG architecture ----------
hdr "RNG architecture"
ENTAVAIL="$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo NA)"
say "entropy_avail     : $ENTAVAIL"
HWRNG_CUR="$(cat /sys/class/misc/hw_random/rng_current 2>/dev/null || echo none)"
HWRNG_AVL="$(cat /sys/class/misc/hw_random/rng_available 2>/dev/null || echo none)"
say "hwrng current     : $HWRNG_CUR"
say "hwrng available   : $HWRNG_AVL"
VIRTIO=no; printf '%s' "$HWRNG_AVL $HWRNG_CUR" | grep -qi virtio && VIRTIO=yes
say "virtio-rng        : $VIRTIO"
JITTER=no; grep -qi jitterentropy /proc/crypto 2>/dev/null && JITTER=yes
say "jitterentropy_rng : $JITTER"
RNGD=no; pgrep -x rngd >/dev/null 2>&1 && RNGD=yes
HAVEGED=no; pgrep -x haveged >/dev/null 2>&1 && HAVEGED=yes
say "rngd / haveged    : $RNGD / $HAVEGED"
GETRANDOM=no; command -v python3 >/dev/null 2>&1 && python3 -c "import os;os.getrandom(1)" 2>/dev/null && GETRANDOM=yes
say "getrandom(2)      : $GETRANDOM"
# boot-time crng init (BSI VM study: this is delayed under virtualization)
CRNG="$(dmesg 2>/dev/null | grep -i 'crng init done' | head -1 | sed 's/\[//;s/\]//' | awk '{print $1}')"
say "crng init done @  : ${CRNG:-unknown} s (dmesg may need root)"
# vmfork / vmgenid (snapshot/clone reset protection; merged ~5.18)
VMGENID=no; dmesg 2>/dev/null | grep -qi vmgenid && VMGENID=yes
say "vmgenid driver    : $VMGENID"

# ---------- 4. BSI AIS 20/31 kernel mapping (Dec 2025 table) ----------
hdr "BSI AIS 20/31 kernel mapping"
KVER="$KMAJ.$KMIN"
ais="unknown"
verge() { # $1>=$2 by major.minor
  [ "$KMAJ" -gt "$1" ] && return 0
  [ "$KMAJ" -eq "$1" ] && [ "$KMIN" -ge "$2" ] && return 0
  return 1
}
if   verge 5 18; then ais="NONE (no formal AIS 20/31: DRT.1.4 request-length limit unmet; NOT a crypto weakness)"
elif verge 5 6 ; then ais="DRG.3"
elif verge 4 9 ; then ais="NTG.1"
else ais="pre-4.9 (not in BSI table)"; fi
say "Kernel $KVER -> AIS 20/31: $ais"

# ---------- 5. RNG construction (kernel-version-gated, NOT hardcoded) ----------
# The user-facing CSPRNG construction depends on the kernel version. We assert it
# only where the version maps to a documented implementation; otherwise we report
# EVIDENCE-NEEDED rather than guessing. (random.c moved to a ChaCha-based DRNG in
# the 4.8 era and to the BLAKE2s pool + ChaCha20 fast-key-erasure design in 5.17/5.18.)
hdr "Kernel RNG construction (version-gated)"
if   verge 5 17; then
  CSPRNG="ChaCha20 DRNG with BLAKE2s input pool + fast key erasure"; CSPRNG_KNOWN=yes
elif verge 4 8 ; then
  CSPRNG="ChaCha20-based DRNG (pre-5.17 random.c)"; CSPRNG_KNOWN=yes
else
  CSPRNG="EVIDENCE-NEEDED (kernel < 4.8; map random.c implementation to a cited source before asserting)"; CSPRNG_KNOWN=no
fi
say "CSPRNG construction: $CSPRNG"

hdr "ENISA sound-criteria mapping (Linux getrandom/urandom)"
say "  basis tags: [measured]=read from this host  [derived]=computed from measured kernel version  [design]=documented property of the Linux RNG, NOT verified on this host"
if [ "$CSPRNG_KNOWN" = yes ]; then
  say "[DEVIATES] [derived] Agreed DRBG = HMAC/Hash/CTR_DRBG (SP800-90A)"
  say "                This kernel's user-facing CSPRNG is a ChaCha20-based DRNG; NOT on ENISA's"
  say "                three-DRBG agreed list. For an ENISA agreed-DRBG posture use a SP800-90A DRBG"
  say "                (kernel 'drbg' module / jitterentropy, or userspace) seeded from the kernel."
  say "[MEETS] [design] Backtracking resistance for PFS (Note 70) — ChaCha20 fast key erasure (5.17+ confirmed; 4.8–5.16 via reseed)."
else
  say "[EVIDENCE-NEEDED] [derived] Agreed-DRBG verdict withheld: CSPRNG construction not established for this kernel."
  say "[EVIDENCE-NEEDED] [derived] Backtracking-resistance verdict withheld pending construction evidence."
fi
say "[MEETS] [design] TRNG only seeds DRBG; no direct TRNG output (Note 67) — getrandom exposes DRBG only (Linux RNG architecture, not verified on this host)."
say "[MEETS] [design] Seed min-entropy >=125 (Note 68) — kernel collects 256 bits before fully-seeded (documented Linux behaviour; entropy budget not measured here)."
say "[EVIDENCE-NEEDED] [design] Source modeling (preferred, §7.1 approach 2) — establish via the BSI LRNG study; not produced by this script."
if [ "$EC2" = yes ] || [ "$VIRT" != "none" -a "$VIRT" != "unknown" ]; then
  say "[VM-RISK] [measured] Snapshot/clone state reuse — needs vmgenid/vmfork (>=5.18). vmgenid=$VMGENID (measured)."
  say "[VM-RISK] [design] Boot-time entropy reduced under virtualization (BSI 'Randomness in VMs'); see crng-init timing above."
  say "[VM-INFO] [measured] Prefer hwrng/virtio-rng passthrough; virtio-rng=$VIRTIO, RDRAND=$RDRAND (measured)."
fi

# ---------- 6. Raw sample (failure-detection sanity only) ----------
hdr "Emitting RNG sample (sanity check only, NOT compliance evidence)"
head -c 1250000 /dev/urandom > linux_rng_sample.bin 2>/dev/null && \
  say "wrote linux_rng_sample.bin (1250000 bytes). Optional: python3 ../critique/battery.py linux_rng_sample.bin"

# ---------- 7. JSON ----------
hdr "Writing JSON"
cat > linux_assessment.json <<JSON
{
  "target": "$( [ "$EC2" = yes ] && echo ec2-vm || ([ "$IS_WSL" = yes ] && echo wsl || echo linux) )",
  "timestamp": "$(date -u +%FT%TZ)",
  "platform": { "kernel": "$(J "$KREL")", "virt": "$(J "$VIRT")", "wsl": "$IS_WSL", "ec2": "$EC2" },
  "hardware": { "cpu": "$(J "$CPU")", "logical_cpus": "$CORES", "rdrand": "$RDRAND",
                "rdseed": "$RDSEED", "mem_mb": $((MEMKB/1024)) },
  "rng": { "entropy_avail": "$ENTAVAIL", "hwrng_current": "$(J "$HWRNG_CUR")",
           "virtio_rng": "$VIRTIO", "jitterentropy": "$JITTER", "rngd": "$RNGD",
           "haveged": "$HAVEGED", "getrandom": "$GETRANDOM", "crng_init_done_s": "${CRNG:-unknown}",
           "vmgenid": "$VMGENID", "csprng": "$(J "$CSPRNG")", "csprng_known": "$CSPRNG_KNOWN",
           "on_enisa_agreed_list": $( [ "$CSPRNG_KNOWN" = yes ] && echo false || echo null ) },
  "bsi_ais2031": "$(J "$ais")",
  "verdicts": {
    "agreed_drbg_algorithm": "$( [ "$CSPRNG_KNOWN" = yes ] && echo DEVIATES || echo EVIDENCE-NEEDED )",
    "trng_seeds_drbg_only": "MEETS",
    "seed_min_entropy_125": "MEETS",
    "backtracking_resistance": "$( [ "$CSPRNG_KNOWN" = yes ] && echo MEETS || echo EVIDENCE-NEEDED )",
    "source_modeling": "EVIDENCE-NEEDED"
  }
}
JSON
say "wrote linux_assessment.json"
