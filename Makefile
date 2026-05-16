.PHONY: install build start dev test test-coverage clean rebuild open

# Install dependencies
install:
	npm install

# Compile TypeScript
build:
	npx tsc

# Run the tracker (build first)
start: build
	node dist/index.js

# Dev: build + run in one shot
dev:
	npx tsc && node dist/index.js

# Run unit tests
test: build
	npm run test:unit

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

# Delete build output
clean:
	rm -rf dist

# Full clean rebuild
rebuild: clean install build
