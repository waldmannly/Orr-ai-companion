# Orr — PowerShell launcher
# Usage:
#   .\run.ps1           → build + start
#   .\run.ps1 dev       → build + start + open browser
#   .\run.ps1 test      → build + run tests
#   .\run.ps1 coverage  → tests with HTML coverage report
#   .\run.ps1 build     → compile only
#   .\run.ps1 open      → open dashboard in browser
#   .\run.ps1 status    → check if server is running
#   .\run.ps1 logs      → show DB file sizes
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
        Write-Step "Starting tracker on http://127.0.0.1:3847 ..."
        node dist/index.js
    }
    "dev" {
        Write-Step "Building..."
        npx tsc
        if ($LASTEXITCODE -ne 0) { throw "Build failed" }
        Write-Step "Starting tracker..."
        Start-Process -FilePath "node" -ArgumentList "dist/index.js" -WindowStyle Hidden
        Start-Sleep -Seconds 1
        Start-Process "http://127.0.0.1:3847"
        Write-Host "  ✓ Server started + browser opened" -ForegroundColor Green
    }
    "test" {
        Write-Step "Building..."
        npx tsc
        if ($LASTEXITCODE -ne 0) { throw "Build failed" }
        Write-Step "Running tests..."
        npm test
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
    "status" {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:3847/api/stats" -UseBasicParsing -TimeoutSec 2
            Write-Host "  ✓ Server is running" -ForegroundColor Green
            $r.Content | ConvertFrom-Json | Format-List
        } catch {
            Write-Host "  ✗ Server is not running" -ForegroundColor Red
        }
    }
    "logs" {
        if (Test-Path data) {
            Get-ChildItem data -Recurse | Select-Object Name, @{N='Size';E={'{0:N1} MB' -f ($_.Length/1MB)}} | Format-Table -AutoSize
        } else {
            Write-Host "  No data directory yet" -ForegroundColor Yellow
        }
    }
    "clean" {
        Write-Step "Cleaning dist/..."
        if (Test-Path dist) { Remove-Item -Recurse -Force dist }
        Write-Host "  ✓ Clean" -ForegroundColor Green
    }
    default {
        Write-Host "Unknown command: $Command" -ForegroundColor Red
        Write-Host "Usage: .\run.ps1 [start|dev|build|test|coverage|open|status|logs|clean|install]"
    }
}
