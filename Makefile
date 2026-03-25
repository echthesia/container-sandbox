PLUGIN_NAME = sandbox
BUILD_CONFIG ?= release
SWIFT_BUILD_FLAGS = -c $(BUILD_CONFIG)

# Stable install location (survives brew upgrades)
STABLE_DIR = $(HOME)/.local/lib/container-sandbox

# Plugin directory inside container's install root
CONTAINER_PREFIX = $(shell brew --prefix container 2>/dev/null)
PLUGIN_DIR = $(CONTAINER_PREFIX)/libexec/container-plugins/$(PLUGIN_NAME)

INIT_IMAGE_TAG = container-sandbox-init:latest

.PHONY: build install link uninstall clean init-image

build:
	swift build $(SWIFT_BUILD_FLAGS)

# Full install: copy binary to stable location + create symlink
install: build
	@if [ -z "$(CONTAINER_PREFIX)" ]; then echo "Error: container not installed via Homebrew"; exit 1; fi
	@echo "Installing to $(STABLE_DIR)"
	mkdir -p "$(STABLE_DIR)/bin"
	cp ".build/$(BUILD_CONFIG)/$(PLUGIN_NAME)" "$(STABLE_DIR)/bin/$(PLUGIN_NAME)"
	codesign -fs - "$(STABLE_DIR)/bin/$(PLUGIN_NAME)"
	cp Plugin/config.json "$(STABLE_DIR)/config.json"
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

init-image:
	cd init-image && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o init-wrapper ./cmd/init-wrapper
	cd init-image && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o proxy-bridge ./cmd/proxy-bridge
	container build --tag $(INIT_IMAGE_TAG) \
		--build-arg VMINIT_TAG=$$(container system property get image.init | sed 's/.*://') \
		--file init-image/Containerfile init-image/

clean:
	swift package clean
	rm -f init-image/init-wrapper init-image/proxy-bridge
