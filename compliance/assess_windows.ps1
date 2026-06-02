<#
  assess_windows.ps1 — ENISA ACM host RNG posture for a Windows laptop.
  Sound criteria only (statistical testing is NOT used as a compliance criterion).

  Run (no admin needed for most fields; TPM/FIPS read benefits from admin):
      powershell -ExecutionPolicy Bypass -File .\assess_windows.ps1

  Outputs:
      windows_assessment.json    machine-readable findings + inventory
      windows_rng_sample.bin     10,000,000 bits from the CNG CSPRNG
                                 (optional failure-detection sanity check only)
#>

$ErrorActionPreference = "SilentlyContinue"
function Section($t){ Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# ---------- 1. Hardware & platform inventory ----------
Section "Hardware & platform inventory"
$cpu   = Get-CimInstance Win32_Processor | Select-Object -First 1
$os    = Get-CimInstance Win32_OperatingSystem
$cs    = Get-CimInstance Win32_ComputerSystem
$bios  = Get-CimInstance Win32_BIOS
$board = Get-CimInstance Win32_BaseBoard
$encl  = Get-CimInstance Win32_SystemEnclosure
$ramGB = [math]::Round(($cs.TotalPhysicalMemory/1GB),1)

# RDRAND/RDSEED: not directly exposed by WMI; heuristic from CPU + note.
$cpuName = $cpu.Name
$rdrandLikely = $cpuName -match "Intel|AMD"   # Ivy Bridge+/AMD Excavator+ have RDRAND
Write-Host ("CPU            : {0}" -f $cpuName)
Write-Host ("Cores/Threads  : {0}/{1}" -f $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors)
Write-Host ("Architecture   : {0}-bit" -f $cpu.AddressWidth)
Write-Host ("RAM            : {0} GB" -f $ramGB)
Write-Host ("Manufacturer   : {0}" -f $cs.Manufacturer)
Write-Host ("Model          : {0}" -f $cs.Model)
Write-Host ("Serial (BIOS)  : {0}" -f $bios.SerialNumber)
Write-Host ("Board          : {0} {1}" -f $board.Manufacturer, $board.Product)
Write-Host ("BIOS           : {0} {1}" -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion)
Write-Host ("OS             : {0} (build {1})" -f $os.Caption, $os.BuildNumber)
Write-Host ("RDRAND/RDSEED  : {0} [heuristic from CPU vendor; verify with Sysinternals coreinfo -f or the Linux /proc/cpuinfo read]" -f ($(if($rdrandLikely){"likely present"}else{"unknown"})))

# TPM
$tpm = Get-Tpm
$tpmObj = Get-CimInstance -Namespace "root/cimv2/security/microsofttpm" -ClassName Win32_Tpm
Write-Host ("TPM present    : {0}" -f $tpm.TpmPresent)
Write-Host ("TPM ready      : {0}" -f $tpm.TpmReady)
Write-Host ("TPM spec ver   : {0}" -f $tpmObj.SpecVersion)
Write-Host ("TPM manufactur : {0}" -f $tpmObj.ManufacturerIdTxt)

# FIPS policy
$fips = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -ErrorAction SilentlyContinue).Enabled
Write-Host ("FIPS policy    : {0}" -f ($(if($fips -eq 1){"ENABLED"}elseif($fips -eq 0){"disabled"}else{"unknown"})))

# Virtualization
Write-Host ("HypervisorPres : {0}" -f $cs.HypervisorPresent)

# ---------- 2. RNG architecture mapped to ENISA sound criteria ----------
Section "ENISA sound-criteria mapping (Windows CNG)"
Write-Host "  basis tags: [measured]=read from this host  [design]=documented property of Windows CNG, NOT verified on this host"
$findings = @(
  @{ req="Agreed DRBG = HMAC/Hash/CTR_DRBG (SP800-90A)"; verdict="MEETS"; basis="design";
     note="Windows CNG (BCryptGenRandom/ProcessPrng) uses AES-256 CTR_DRBG per SP800-90A; on ENISA's agreed DRBG list (Note 71 quantum key-size satisfied at 256-bit). Documented design, not verified on this host." }
  @{ req="TRNG only seeds DRBG; no direct TRNG output (Note 67)"; verdict="MEETS"; basis="design";
     note="User-facing API returns DRBG output only; raw entropy sources (RDRAND/RDSEED/TPM/interrupt timing) feed the seed, not the caller." }
  @{ req="Seed min-entropy >=125 bits (Note 68)"; verdict="MEETS"; basis="design";
     note="CNG reseeds from multiple entropy sources; FIPS-validated builds document >=256-bit seeding. Entropy budget not measured here." }
  @{ req="Backtracking resistance for PFS (Note 70)"; verdict="MEETS"; basis="design";
     note="CTR_DRBG state update + periodic reseed prevent practical recovery of past output from current state." }
  @{ req="Quantum seed >=188 bits (Note 69)"; verdict="CONDITIONAL"; basis="design";
     note="Only if a quantum-resistant posture is claimed; verify seeding entropy budget for that context." }
  @{ req="FIPS 140 validation"; verdict=$(if($fips -eq 1){"MEETS (policy on)"}else{"EVIDENCE-NEEDED"}); basis="measured";
     note="FIPS policy state read from registry (this host). CMVP certificates exist per Windows build; enabling FIPS policy enforces validated algorithms." }
)
foreach($f in $findings){ Write-Host ("[{0}] [{1}] {2}" -f $f.verdict, $f.basis, $f.req); Write-Host ("        {0}" -f $f.note) }

# ---------- 3. Raw sample (failure-detection sanity only) ----------
Section "Emitting RNG sample (sanity check only, NOT compliance evidence)"
$n = 1250000
$buf = New-Object byte[] $n
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($buf)
[System.IO.File]::WriteAllBytes("$PWD\windows_rng_sample.bin", $buf)
Write-Host "wrote windows_rng_sample.bin ($n bytes). Optional: feed to ../critique/battery.py"

# ---------- 4. JSON ----------
$out = [ordered]@{
  target="windows-laptop"; timestamp=(Get-Date).ToString("o")
  hardware=[ordered]@{ cpu=$cpuName; cores=$cpu.NumberOfCores; threads=$cpu.NumberOfLogicalProcessors;
     arch_bits=$cpu.AddressWidth; ram_gb=$ramGB; manufacturer=$cs.Manufacturer; model=$cs.Model;
     serial=$bios.SerialNumber; board=("{0} {1}" -f $board.Manufacturer,$board.Product);
     bios=("{0} {1}" -f $bios.Manufacturer,$bios.SMBIOSBIOSVersion);
     tpm_present=$tpm.TpmPresent; tpm_ready=$tpm.TpmReady; tpm_spec=$tpmObj.SpecVersion;
     rdrand_likely=$rdrandLikely; hypervisor_present=$cs.HypervisorPresent }
  os=[ordered]@{ caption=$os.Caption; build=$os.BuildNumber; fips_policy=$fips }
  rng=[ordered]@{ csprng="CNG BCryptGenRandom/ProcessPrng"; drbg="AES-256 CTR_DRBG (SP800-90A)";
     on_enisa_agreed_list=$true }
  findings=$findings
}
$out | ConvertTo-Json -Depth 6 | Out-File "windows_assessment.json" -Encoding utf8
Write-Host "`nwrote windows_assessment.json"
