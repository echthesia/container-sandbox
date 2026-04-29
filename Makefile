PLUGIN_NAME = sandbox
BUILD_CONFIG ?= release
SWIFT_BUILD_FLAGS = -c $(BUILD_CONFIG)

# Stable install location (survives brew upgrades)
STABLE_DIR = $(HOME)/.local/lib/container-sandbox

# Plugin directory inside container's install root
CONTAINER_PREFIX = $(shell brew --prefix container 2>/dev/null)
PLUGIN_DIR = $(CONTAINER_PREFIX)/libexec/container-plugins/$(PLUGIN_NAME)

.PHONY: build install link uninstall clean init-binaries verify lint test

build:
	swift build $(SWIFT_BUILD_FLAGS)

# Cross-compile the in-container helpers for Linux. Both are mounted into
# containers via virtiofs at /opt/sandbox: sandbox-init is PID 2 (under
# vminitd), proxy-bridge is the long-running TCP↔UDS relay it manages.
init-binaries:
	cd init-image && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) go build -o proxy-bridge ./cmd/proxy-bridge
	cd init-image && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) go build -o sandbox-init ./cmd/sandbox-init
	mkdir -p "$(STABLE_DIR)/libexec"
	cp init-image/proxy-bridge "$(STABLE_DIR)/libexec/proxy-bridge"
	cp init-image/sandbox-init "$(STABLE_DIR)/libexec/sandbox-init"

# Full install: copy binary to stable location + create symlink
install: build init-binaries
	@if [ -z "$(CONTAINER_PREFIX)" ]; then echo "Error: container not installed via Homebrew"; exit 1; fi
	@echo "Installing to $(STABLE_DIR)"
	mkdir -p "$(STABLE_DIR)/bin"
	cp ".build/$(BUILD_CONFIG)/$(PLUGIN_NAME)" "$(STABLE_DIR)/bin/$(PLUGIN_NAME)"
	codesign -fs - "$(STABLE_DIR)/bin/$(PLUGIN_NAME)"
	cp Plugin/config.toml "$(STABLE_DIR)/config.toml"
	rm -f "$(STABLE_DIR)/config.json"
	$(MAKE) link
	@echo "Done. Run 'container sandbox --help' to verify."

# Create/update symlink from container plugin dir to stable location
link:
	@if [ -z "$(CONTAINER_PREFIX)" ]; then echo "Error: container not installed via Homebrew"; exit 1; fi
	@echo "Linking $(PLUGIN_DIR) -> $(STABLE_DIR)"
	rm -f "$(PLUGIN_DIR)"
	ln -s "$(STABLE_DIR)" "$(PLUGIN_DIR)"

uninstall:
	@echo "Removing $(PLUGIN_DIR) and $(STABLE_DIR)"
	rm -f "$(PLUGIN_DIR)"
	rm -rf "$(STABLE_DIR)"

verify: lint test  ## Run full verification suite

lint:  ## Run SwiftLint
	@if command -v swiftlint >/dev/null 2>&1; then \
		swiftlint lint --quiet; \
	else \
		echo "warning: swiftlint not installed, skipping lint"; \
	fi

test:  ## Run hermetic test suite
	swift test

clean:
	swift package clean
	rm -f init-image/proxy-bridge init-image/sandbox-init
