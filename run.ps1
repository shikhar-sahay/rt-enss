param(
    [switch]$NoPython,
    [switch]$NoRebuild
)

$ErrorActionPreference = "Stop"

$SYSTEMC_INC  = "C:/Users/sahay/systemc/include"
$SYSTEMC_LIB  = "C:/Users/sahay/systemc/lib"
$GPP          = "C:\msys64\ucrt64\bin\g++.exe"
$SRC_DIR      = $PSScriptRoot
$EXE          = Join-Path $SRC_DIR "simulation.exe"
$MAIN         = Join-Path $SRC_DIR "main.cpp"
$DASH         = Join-Path $SRC_DIR "dashboard.py"
$PYTHON       = "python"

Write-Host "RT-ENSS v2.0 - Real-Time Embedded Network Security Simulator" -ForegroundColor Cyan
Write-Host "Nodes: 4 | Attacks: Spoofing + Replay + DoS | IDS: Multi-vector" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Path $GPP)) {
    Write-Host "[ERROR] g++ not found at: $GPP" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "$SYSTEMC_INC/systemc.h")) {
    Write-Host "[ERROR] systemc.h not found at: $SYSTEMC_INC" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "$SYSTEMC_LIB/libsystemc.a")) {
    Write-Host "[ERROR] libsystemc.a not found at: $SYSTEMC_LIB" -ForegroundColor Red
    exit 1
}

if (-not $NoRebuild) {
    Write-Host "[1/3] Compiling..." -ForegroundColor Yellow
    & $GPP -std=c++17 -O2 -I"$SYSTEMC_INC" -L"$SYSTEMC_LIB" "$MAIN" -o "$EXE" -lsystemc -lws2_32
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Compilation failed." -ForegroundColor Red
        exit 1
    }
    Write-Host "[1/3] Compilation successful." -ForegroundColor Green
} else {
    Write-Host "[1/3] Skipping recompile." -ForegroundColor Gray
}

if ($NoPython) {
    Write-Host "[2/3] Running simulation (console mode)..." -ForegroundColor Yellow
    & "$EXE"
    Write-Host "[3/3] Done. Run: gtkwave rt_enss_trace.vcd" -ForegroundColor Green
} else {
    $pyCheck = & $PYTHON --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[WARN] Python not found, running console mode." -ForegroundColor Yellow
        & "$EXE"
    } else {
        Write-Host "[2/3] $pyCheck found." -ForegroundColor Green
        Write-Host "[3/3] Launching dashboard..." -ForegroundColor Yellow
        & $PYTHON "$DASH" "$EXE"
    }
}
