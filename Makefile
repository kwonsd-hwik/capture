BIN := .build/release/ChromeTracker
APP_NAME := ChromeTracker
BUILD_BUNDLE_ROOT := .build/chrome-tracker-app
APP_BUNDLE := $(BUILD_BUNDLE_ROOT)/$(APP_NAME).app
APP_MACOS := $(APP_BUNDLE)/Contents/MacOS
APP_RESOURCES := $(APP_BUNDLE)/Contents/Resources
APP_PLIST := $(APP_BUNDLE)/Contents/Info.plist
INFO_PLIST_TEMPLATE := Resources/Info.plist
DIST := dist
DMG_STAGING := $(DIST)/dmg-staging
DATE := $(shell date +%Y-%m-%d)
DMG_NAME := $(DIST)/$(APP_NAME)-$(DATE).dmg
PKG_NAME := $(DIST)/$(APP_NAME)-$(DATE).pkg
PKG_IDENTIFIER := com.example.ChromeTracker

.PHONY: all build release run app dmg pkg install-pkg menu export-json export-csv clean help

all: build

build:
	swift build

release:
	swift build -c release

run: release
	$(BIN)

app: release
	@mkdir -p $(BUILD_BUNDLE_ROOT)
	@rm -rf $(APP_BUNDLE)
	@mkdir -p $(APP_MACOS) $(APP_RESOURCES)
	@cp $(BIN) $(APP_MACOS)/$(APP_NAME)
	@chmod +x $(APP_MACOS)/$(APP_NAME)
	@cp $(INFO_PLIST_TEMPLATE) $(APP_PLIST)
	@cp Resources/AppIcon.icns $(APP_RESOURCES)/
	@echo "Bundle generated: $(APP_BUNDLE)"

dmg: app
	@mkdir -p $(DIST)
	@rm -rf $(DMG_STAGING)
	@mkdir -p $(DMG_STAGING)
	@cp -R $(APP_BUNDLE) $(DMG_STAGING)/
	@ln -s /Applications $(DMG_STAGING)/Applications
	@hdiutil create -volname "$(APP_NAME) Installer" -srcfolder $(DMG_STAGING) -ov -format UDZO $(DMG_NAME)
	@rm -rf $(DMG_STAGING)
	@echo "Installer generated: $(DMG_NAME)"

pkg: app
	@mkdir -p $(DIST)
	@pkgbuild \
		--component $(APP_BUNDLE) \
		--install-location /Applications \
		--identifier $(PKG_IDENTIFIER) \
		--version 1.0.0 \
		$(PKG_NAME)
	@echo "PKG generated: $(PKG_NAME)"

install-pkg: pkg
	@sudo installer -pkg $(PKG_NAME) -target /
	@echo "Installed to /Applications via pkg"

menu: release
	$(BIN)

export-json: release
	$(BIN) --export-json $(if $(path),$(path),$(HOME)/Downloads/ChromeTracker-$(DATE).json)

export-csv: release
	$(BIN) --export-csv $(if $(path),$(path),$(HOME)/Downloads/ChromeTracker-$(DATE).csv)

clean:
	rm -rf .build $(DIST)

help:
	@echo "Usage:"
	@echo "  make build        # debug build"
	@echo "  make release      # release build"
	@echo "  make run          # run menu-bar app (release)"
	@echo "  make app          # build app bundle"
	@echo "  make dmg          # build installer DMG"
	@echo "  make pkg          # build PKG installer"
	@echo "  make install-pkg  # install PKG to /Applications"
	@echo "  make export-json [path=...]"
	@echo "  make export-csv [path=...]"
	@echo "  make clean"
