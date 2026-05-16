# AL Companion Tracker — PowerShell launcher
# Usage:
#   .\run.ps1           → build + start
#   .\run.ps1 test      → build + run tests
#   .\run.ps1 coverage  → tests with HTML coverage report
#   .\run.ps1 build     → compile only
#   .\run.ps1 open      → open dashboard in browser
#   .\run.ps1 clean     → delete dist/
#   .\run.ps1 install   → npm install

param([string]$Command = "start")

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "  → $msg" -ForegroundColor Cyan }

switch ($Command) {
    "install" {
        Write-Step "Installing dependencies..."
        npm install
    }
    "build" {
        Write-Step "Compiling TypeScript..."
        npx tsc
        if ($LASTEXITCODE -ne 0) { throw "Build failed" }
        Write-Host "  ✓ Build complete" -ForegroundColor Green
    }
    "start" {
        Write-Step "Building..."
        npx tsc
        if ($LASTEXITCODE -ne 0) { throw "Build failed" }
        Write-Step "Starting tracker..."
        node dist/index.js
    }
    "test" {
        Write-Step "Building..."
        npx tsc
        if ($LASTEXITCODE -ne 0) { throw "Build failed" }
        Write-Step "Running tests..."
        npm run test:unit
    }
    "coverage" {
        Write-Step "Building..."
        npx tsc
        if ($LASTEXITCODE -ne 0) { throw "Build failed" }
        Write-Step "Running tests with coverage..."
        npm run test:coverage
    }
    "open" {
        Start-Process "http://127.0.0.1:3847"
    }
    "clean" {
        Write-Step "Cleaning dist/..."
        if (Test-Path dist) { Remove-Item -Recurse -Force dist }
        Write-Host "  ✓ Clean" -ForegroundColor Green
    }
    default {
        Write-Host "Unknown command: $Command" -ForegroundColor Red
        Write-Host "Usage: .\run.ps1 [start|build|test|coverage|open|clean|install]"
    }
}
