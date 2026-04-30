PLUGIN_NAME = sandbox
BUILD_CONFIG ?= release
SWIFT_BUILD_FLAGS = -c $(BUILD_CONFIG)

# Stable install location (survives brew upgrades)
STABLE_DIR = $(HOME)/.local/lib/container-sandbox

# Plugin directory inside container's install root
CONTAINER_PREFIX = $(shell brew --prefix container 2>/dev/null)
PLUGIN_DIR = $(CONTAINER_PREFIX)/libexec/container-plugins/$(PLUGIN_NAME)

# Release packaging
VERSION ?= dev
HOST_ARCH = $(shell uname -m | sed 's/x86_64/amd64/')
DIST_DIR = dist
PACKAGE_NAME = container-sandbox-$(VERSION)-$(HOST_ARCH)
PACKAGE_DIR = $(DIST_DIR)/$(PACKAGE_NAME)
PACKAGE_TGZ = $(DIST_DIR)/$(PACKAGE_NAME).tar.gz

# Signing. Defaults to ad-hoc (`-`); for distribution set both to your
# Developer ID identity and a `notarytool store-credentials` profile name.
#   make package VERSION=v0.1.0 \
#       SIGN_IDENTITY="Developer ID Application: <Name> (<TeamID>)" \
#       NOTARY_PROFILE=<profile>
SIGN_IDENTITY ?= -
NOTARY_PROFILE ?=

.PHONY: build install link uninstall clean init-binaries verify lint test package

build:
	swift build $(SWIFT_BUILD_FLAGS)

# Cross-compile the in-container helpers for Linux. Both are mounted into
# containers via virtiofs at /opt/sandbox: sandbox-init is PID 2 (under
# vminitd), proxy-bridge is the long-running TCP↔UDS relay it manages.
init-binaries:
	cd init-image && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) go build -o proxy-bridge ./cmd/proxy-bridge
	cd init-image && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) go build -o sandbox-init ./cmd/sandbox-init

# Full install: copy binary to stable location + create symlink
install: build init-binaries
	@if [ -z "$(CONTAINER_PREFIX)" ]; then echo "Error: container not installed via Homebrew"; exit 1; fi
	@echo "Installing to $(STABLE_DIR)"
	mkdir -p "$(STABLE_DIR)/bin" "$(STABLE_DIR)/libexec"
	cp ".build/$(BUILD_CONFIG)/$(PLUGIN_NAME)" "$(STABLE_DIR)/bin/$(PLUGIN_NAME)"
	codesign -fs - "$(STABLE_DIR)/bin/$(PLUGIN_NAME)"
	cp init-image/proxy-bridge "$(STABLE_DIR)/libexec/proxy-bridge"
	cp init-image/sandbox-init "$(STABLE_DIR)/libexec/sandbox-init"
	cp Plugin/config.toml "$(STABLE_DIR)/config.toml"
	rm -f "$(STABLE_DIR)/config.json"
	$(MAKE) link
	@echo "Done. Run 'container sandbox --help' to verify."

# Build a release tarball at $(PACKAGE_TGZ). Layout matches STABLE_DIR so
# downstream packagers (brew tap, install.sh) can drop it in directly.
# Override VERSION on the command line, e.g. `make package VERSION=v0.1.0`.
# Hardened-runtime signing uses --options runtime (required for notarization);
# notarization runs only when NOTARY_PROFILE is set.
package: build init-binaries
	rm -rf "$(PACKAGE_DIR)"
	mkdir -p "$(PACKAGE_DIR)/bin" "$(PACKAGE_DIR)/libexec"
	cp ".build/$(BUILD_CONFIG)/$(PLUGIN_NAME)" "$(PACKAGE_DIR)/bin/$(PLUGIN_NAME)"
	@if [ "$(SIGN_IDENTITY)" = "-" ]; then \
		echo "codesign --force --sign - (ad-hoc) $(PACKAGE_DIR)/bin/$(PLUGIN_NAME)"; \
		codesign -fs - "$(PACKAGE_DIR)/bin/$(PLUGIN_NAME)"; \
	else \
		echo "codesign --force --sign $(SIGN_IDENTITY) --options runtime --timestamp"; \
		codesign -fs "$(SIGN_IDENTITY)" --options runtime --timestamp "$(PACKAGE_DIR)/bin/$(PLUGIN_NAME)"; \
	fi
	cp init-image/proxy-bridge "$(PACKAGE_DIR)/libexec/proxy-bridge"
	cp init-image/sandbox-init "$(PACKAGE_DIR)/libexec/sandbox-init"
	cp Plugin/config.toml "$(PACKAGE_DIR)/config.toml"
	@if [ -n "$(NOTARY_PROFILE)" ]; then \
		echo "Notarizing $(PACKAGE_DIR)/bin/$(PLUGIN_NAME) with profile $(NOTARY_PROFILE)..."; \
		ditto -c -k --keepParent "$(PACKAGE_DIR)/bin/$(PLUGIN_NAME)" "$(DIST_DIR)/notarize.zip"; \
		xcrun notarytool submit "$(DIST_DIR)/notarize.zip" --keychain-profile "$(NOTARY_PROFILE)" --wait; \
		rm -f "$(DIST_DIR)/notarize.zip"; \
		codesign --verify --strict --verbose=2 "$(PACKAGE_DIR)/bin/$(PLUGIN_NAME)"; \
	fi
	tar -C "$(DIST_DIR)" -czf "$(PACKAGE_TGZ)" "$(PACKAGE_NAME)"
	shasum -a 256 "$(PACKAGE_TGZ)" | tee "$(PACKAGE_TGZ).sha256"
	@echo "Packaged $(PACKAGE_TGZ)"

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
	rm -rf "$(DIST_DIR)"
