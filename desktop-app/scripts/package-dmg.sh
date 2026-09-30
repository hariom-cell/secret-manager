#!/usr/bin/env bash
# Package Secret Manager Desktop as .dmg (macOS)
set -euo pipefail

VERSION="${1:-0.1.0}"
OUT_DIR="dist"
mkdir -p "$OUT_DIR"

echo "Building release binary..."
cargo build --release --locked --manifest-path src-tauri/Cargo.toml

APP_NAME="Secret Manager"
BINARY="target/x86_64-apple-darwin/release/secret-manager-desktop"

# Create app bundle structure
APP_BUNDLE="$OUT_DIR/${APP_NAME}.app"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy binary
cp "$BINARY" "$APP_BUNDLE/Contents/MacOS/secret-manager-desktop"
chmod +x "$APP_BUNDLE/Contents/MacOS/secret-manager-desktop"

# Create Info.plist
cat > "$APP_BUNDLE/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>secret-manager-desktop</string>
    <key>CFBundleIdentifier</key>
    <string>com.secret-manager.desktop</string>
    <key>CFBundleName</key>
    <string>Secret Manager</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSAppleEventsUsageDescription</key>
    <string>Required for auto-type feature.</string>
    <key>NSAccessibilityUsageDescription</key>
    <string>Required for auto-type to inject secrets into other apps.</string>
</dict>
</plist>
PLIST

# Create DMG
hdiutil create -volname "$APP_NAME" -srcfolder "$APP_BUNDLE" -ov -format UDZO \
    "$OUT_DIR/secret-manager-${VERSION}-macos.dmg"

echo "DMG: $OUT_DIR/secret-manager-${VERSION}-macos.dmg"
