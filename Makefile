.PHONY: install build start dev test test-coverage clean rebuild open help status logs

# Show available commands
help:
	@echo.
	@echo   Orr
	@echo   ====================
	@echo   make install        Install dependencies
	@echo   make build          Compile TypeScript
	@echo   make start          Build + run server
	@echo   make dev            Build + run + open browser
	@echo   make test           Build + run unit tests
	@echo   make test-coverage  Build + run tests with coverage
	@echo   make open           Open dashboard in browser
	@echo   make status         Check if server is running
	@echo   make logs           Tail the data directory for DB size
	@echo   make clean          Delete build output
	@echo   make rebuild        Clean + install + build
	@echo.

# Install dependencies
install:
	npm install

# Compile TypeScript
build:
	npx tsc

# Run the tracker (build first)
start: build
	node dist/index.js

# Dev: build, run, and open browser
dev: build
ifeq ($(OS),Windows_NT)
	@start /b node dist/index.js
	@timeout /t 1 /nobreak >nul
	@cmd /c start http://127.0.0.1:3847
else
	@node dist/index.js &
	@sleep 1
	@command -v xdg-open >/dev/null 2>&1 && xdg-open http://127.0.0.1:3847 || open http://127.0.0.1:3847
endif

# Run unit tests
test: build
	npm test

# Run tests with HTML coverage report
test-coverage: build
	npm run test:coverage

# Open the dashboard in the default browser
open:
ifeq ($(OS),Windows_NT)
	cmd /c start http://127.0.0.1:3847
else
	@command -v xdg-open >/dev/null 2>&1 && xdg-open http://127.0.0.1:3847 || open http://127.0.0.1:3847
endif

# Check if the server is responding
status:
ifeq ($(OS),Windows_NT)
	@powershell -NoProfile -Command "try { $$r = Invoke-WebRequest -Uri http://127.0.0.1:3847/api/stats -UseBasicParsing -TimeoutSec 2; Write-Host '  Server is running' -ForegroundColor Green; $$r.Content | ConvertFrom-Json | Format-List } catch { Write-Host '  Server is not running' -ForegroundColor Red }"
else
	@curl -sf http://127.0.0.1:3847/api/stats && echo "\n  Server is running" || echo "  Server is not running"
endif

# Show DB size
logs:
ifeq ($(OS),Windows_NT)
	@powershell -NoProfile -Command "Get-ChildItem data -Recurse -ErrorAction SilentlyContinue | Select-Object Name, @{N='Size';E={'{0:N1} MB' -f ($$_.Length/1MB)}} | Format-Table -AutoSize"
else
	@ls -lh data/ 2>/dev/null || echo "  No data directory yet"
endif

# Delete build output
clean:
ifeq ($(OS),Windows_NT)
	@if exist dist rmdir /s /q dist
else
	rm -rf dist
endif

# Full clean rebuild
rebuild: clean install build
