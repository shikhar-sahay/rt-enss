param(
    [switch]$NoPython,
    [switch]$NoRebuild
)

$PROJECT_ROOT = Split-Path $PSScriptRoot -Parent

$SYSTEMC_INC  = "C:/Users/sahay/systemc/include"
$SYSTEMC_LIB  = "C:/Users/sahay/systemc/lib"
$GPP          = "C:\msys64\ucrt64\bin\g++.exe"
$PYTHON       = "python"

$SRC_DIR      = Join-Path $PROJECT_ROOT "src"
$GUI_DIR      = Join-Path $PROJECT_ROOT "gui"
$BIN_DIR      = Join-Path $PROJECT_ROOT "bin"
$OUTPUT_DIR   = Join-Path $PROJECT_ROOT "output"

$MAIN         = Join-Path $SRC_DIR "main.cpp"
$DASH         = Join-Path $GUI_DIR "dashboard.py"
$EXE          = Join-Path $BIN_DIR "simulation.exe"

Write-Host "RT-ENSS v2.0" -ForegroundColor Cyan
Write-Host "PROJECT_ROOT = $PROJECT_ROOT"
Write-Host "SRC_DIR      = $SRC_DIR"
Write-Host "GUI_DIR      = $GUI_DIR"
Write-Host "BIN_DIR      = $BIN_DIR"
Write-Host "OUTPUT_DIR   = $OUTPUT_DIR"
Write-Host "MAIN         = $MAIN"
Write-Host "DASH         = $DASH"
Write-Host "EXE          = $EXE"
Write-Host ""

if (-not (Test-Path $GPP)) {
    Write-Host "[ERROR] g++ not found: $GPP" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path "$SYSTEMC_INC/systemc.h")) {
    Write-Host "[ERROR] systemc.h not found in: $SYSTEMC_INC" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path "$SYSTEMC_LIB/libsystemc.a")) {
    Write-Host "[ERROR] libsystemc.a not found in: $SYSTEMC_LIB" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $MAIN)) {
    Write-Host "[ERROR] main.cpp not found: $MAIN" -ForegroundColor Red
    exit 1
}

if ((-not $NoPython) -and (-not (Test-Path $DASH))) {
    Write-Host "[ERROR] dashboard.py not found: $DASH" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $BIN_DIR)) {
    New-Item -ItemType Directory -Path $BIN_DIR | Out-Null
}

if (-not (Test-Path $OUTPUT_DIR)) {
    New-Item -ItemType Directory -Path $OUTPUT_DIR | Out-Null
}

$headerFiles = @(
    (Join-Path $SRC_DIR "attack.h"),
    (Join-Path $SRC_DIR "ids.h"),
    (Join-Path $SRC_DIR "network.h"),
    (Join-Path $SRC_DIR "node.h"),
    (Join-Path $SRC_DIR "scheduler.h")
)

foreach ($header in $headerFiles) {
    if (-not (Test-Path $header)) {
        Write-Host "[ERROR] Required header not found: $header" -ForegroundColor Red
        exit 1
    }
}

Push-Location $PROJECT_ROOT

try {
    if (-not $NoRebuild) {
        if (Test-Path $EXE) {
            Remove-Item $EXE -Force
        }

        Write-Host "[1/3] Compiling..." -ForegroundColor Yellow

        $compile_output = & $GPP `
            -std=c++17 -O2 `
            -I"$SYSTEMC_INC" `
            -I"$SRC_DIR" `
            -L"$SYSTEMC_LIB" `
            "$MAIN" `
            -o "$EXE" `
            -lsystemc -lws2_32 2>&1

        if ($compile_output) {
            Write-Host $compile_output
        }

        if (-not (Test-Path $EXE)) {
            Write-Host "[ERROR] Compilation failed - simulation.exe was not created." -ForegroundColor Red
            exit 1
        }

        Write-Host "[1/3] Compilation successful." -ForegroundColor Green
    }
    else {
        Write-Host "[1/3] Skipping recompile." -ForegroundColor Gray

        if (-not (Test-Path $EXE)) {
            Write-Host "[ERROR] No simulation.exe found. Run without -NoRebuild first." -ForegroundColor Red
            exit 1
        }
    }

    if ($NoPython) {
        Write-Host "[2/3] Running simulation (console mode)..." -ForegroundColor Yellow
        & "$EXE"
        Write-Host "[3/3] Done." -ForegroundColor Green
    }
    else {
        $pyCheck = & $PYTHON --version 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Host "[WARN] Python not found, running console mode." -ForegroundColor Yellow
            & "$EXE"
            Write-Host "[3/3] Done." -ForegroundColor Green
        }
        else {
            Write-Host "[2/3] $pyCheck" -ForegroundColor Green
            Write-Host "[3/3] Launching dashboard..." -ForegroundColor Yellow
            & $PYTHON "$DASH" "$EXE"
        }
    }
}
finally {
    Pop-Location
}