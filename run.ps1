# RT-ENSS v2.0 — Build & Launch Script
# Usage: ./run.ps1
# Optional: ./run.ps1 -NoPython   (run simulation only, no GUI)
# Optional: ./run.ps1 -NoRebuild  (skip recompile, just run)

param(
    [switch]$NoPython,
    [switch]$NoRebuild
)

$ErrorActionPreference = "Stop"

# ── Configuration ─────────────────────────────────────────────────────────────
# Edit this path to where you installed SystemC
$SYSTEMC_HOME = "$env:USERPROFILE\systemc"
$SYSTEMC_INC  = "$SYSTEMC_HOME\include"
$SYSTEMC_LIB  = "$SYSTEMC_HOME\lib"

$SRC_DIR      = $PSScriptRoot
$EXE          = "$SRC_DIR\simulation.exe"
$PYTHON       = "python"   # or "python3" on some systems

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ██████╗ ████████╗      ███████╗███╗   ██╗███████╗███████╗" -ForegroundColor Cyan
Write-Host "  ██╔══██╗╚══██╔══╝      ██╔════╝████╗  ██║██╔════╝██╔════╝" -ForegroundColor Cyan
Write-Host "  ██████╔╝   ██║   █████╗█████╗  ██╔██╗ ██║███████╗███████╗" -ForegroundColor Cyan
Write-Host "  ██╔══██╗   ██║   ╚════╝██╔══╝  ██║╚██╗██║╚════██║╚════██║" -ForegroundColor Cyan
Write-Host "  ██║  ██║   ██║         ███████╗██║ ╚████║███████║███████║" -ForegroundColor Cyan
Write-Host "  ╚═╝  ╚═╝   ╚═╝         ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Real-Time Embedded Network Security Simulator  v2.0" -ForegroundColor White
Write-Host "  Nodes: 4 | Attacks: Spoofing + Replay + DoS | IDS: Multi-vector" -ForegroundColor DarkGray
Write-Host ""

# ── Check SystemC ─────────────────────────────────────────────────────────────
if (-not (Test-Path $SYSTEMC_INC)) {
    Write-Host "[ERROR] SystemC headers not found at: $SYSTEMC_INC" -ForegroundColor Red
    Write-Host "        Edit SYSTEMC_HOME in run.ps1 to point to your SystemC installation." -ForegroundColor Yellow
    exit 1
}

# ── Compile ───────────────────────────────────────────────────────────────────
if (-not $NoRebuild) {
    Write-Host "[1/3] Compiling SystemC simulation..." -ForegroundColor Yellow

    $sources = @(
        "$SRC_DIR\main.cpp"
    )

    $flags = @(
        "-std=c++17",
        "-O2",
        "-I$SYSTEMC_INC",
        "-L$SYSTEMC_LIB",
        "-o", $EXE
    ) + $sources + @(
        "-lsystemc",
        "-Wl,-rpath,$SYSTEMC_LIB"
    )

    & g++ @flags 2>&1 | Tee-Object -Variable compileOut

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Compilation failed." -ForegroundColor Red
        exit 1
    }
    Write-Host "[1/3] Compilation successful." -ForegroundColor Green
} else {
    Write-Host "[1/3] Skipping recompile (-NoRebuild)." -ForegroundColor DarkGray
}

# ── Copy runtime DLLs if present ─────────────────────────────────────────────
$dlls = @("libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll")
foreach ($dll in $dlls) {
    $src = "$SRC_DIR\$dll"
    if (Test-Path $src) {
        Copy-Item $src -Destination (Split-Path $EXE) -Force
    }
}

# ── Launch ────────────────────────────────────────────────────────────────────
if ($NoPython) {
    # Run simulation directly, print to console
    Write-Host "[2/3] Running simulation (console mode)..." -ForegroundColor Yellow
    Write-Host ""
    & $EXE
    Write-Host ""
    Write-Host "[3/3] Done. VCD trace saved to: rt_enss_trace.vcd" -ForegroundColor Green
    Write-Host "       View with: gtkwave rt_enss_trace.vcd" -ForegroundColor DarkGray
} else {
    # Check Python
    $pyVersion = & $PYTHON --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[WARN] Python not found — falling back to console mode." -ForegroundColor Yellow
        & $EXE
    } else {
        Write-Host "[2/3] Python found: $pyVersion" -ForegroundColor Green
        Write-Host "[3/3] Launching dashboard + simulation..." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "       Dashboard will open. Close it to end the session." -ForegroundColor DarkGray
        Write-Host ""
        & $PYTHON "$SRC_DIR\dashboard.py" $EXE
    }
}
