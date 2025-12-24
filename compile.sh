#!/bin/bash
set -e

APP_NAME="borg-manager"
MAIN_SCRIPT="borg_gui.py"

echo "========================================"
echo "   Compiling $APP_NAME   "
echo "========================================"

# 1. Check/Install PyInstaller
if ! command -v pyinstaller &> /dev/null; then
    echo "[*] PyInstaller not found. Installing..."
    pip3 install pyinstaller
fi

# 2. Clean previous build
echo "[*] Cleaning build folders..."
rm -rf build dist "$APP_NAME.spec"

# 3. Run PyInstaller
# --onefile: Single binary
# --windowed: No terminal window
# --hidden-import: Ensure dynamic imports are caught
echo "[*] Running PyInstaller..."
pyinstaller --noconfirm --onefile --windowed --name "$APP_NAME" \
    --hidden-import "pystray" \
    --hidden-import "PIL" \
    --hidden-import "PIL._tkinter_finder" \
    --hidden-import "matplotlib" \
    --hidden-import "tkinter" \
    "$MAIN_SCRIPT"

echo ""
echo "test compilation by running: ./dist/$APP_NAME"
echo ""

# 4. AppImage Preparation
echo "========================================"
echo "   Preparing AppImage Structure   "
echo "========================================"

APPDIR="AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$APPDIR/usr/share/applications"

# Copy binary
cp "dist/$APP_NAME" "$APPDIR/usr/bin/$APP_NAME"

# Create AppRun
cat > "$APPDIR/AppRun" <<EOF
#!/bin/sh
export PATH="\${APPDIR}/usr/bin:\${PATH}"
export LD_LIBRARY_PATH="\${APPDIR}/usr/lib:\${LD_LIBRARY_PATH}"
exec "$APP_NAME" "\$@"
EOF
chmod +x "$APPDIR/AppRun"

# Create .desktop file
cat > "$APPDIR/$APP_NAME.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Borg Backup Manager
Exec=$APP_NAME
Icon=$APP_NAME
Categories=Utility;System;
Terminal=false
EOF

# Create dummy icon (or copy if exists)
if [ -f "assets/icon.png" ]; then
    cp "assets/icon.png" "$APPDIR/$APP_NAME.png"
    cp "assets/icon.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_NAME.png"
else
    echo "[!] No icon found in assets/icon.png. Generating fallback SVG icon..."
    # Create simple SVG icon
    cat > "$APPDIR/$APP_NAME.svg" <<EOF
<svg width="256" height="256" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg">
  <rect x="10" y="10" width="236" height="236" rx="20" fill="#2c3e50" />
  <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="sans-serif" font-size="140" fill="#ecf0f1">B</text>
</svg>
EOF
    cp "$APPDIR/$APP_NAME.svg" "$APPDIR/usr/share/icons/hicolor/256x256/apps/"
fi

echo "[*] AppDir created at ./$APPDIR"

# 5. Check for appimagetool
APPIMAGETOOL=""

# Check local file first
if [ -f "appimagetool-x86_64.AppImage" ]; then
    APPIMAGETOOL="./appimagetool-x86_64.AppImage"
    chmod +x "$APPIMAGETOOL"
elif command -v appimagetool &> /dev/null; then
    APPIMAGETOOL="appimagetool"
fi

if [ -n "$APPIMAGETOOL" ]; then
    echo "[*] Found appimagetool: $APPIMAGETOOL"
    # Run it
    # Note: appimagetool might require FUSE. If it fails, try with --appimage-extract-and-run or env var.
    # We try standard run first.
    "$APPIMAGETOOL" "$APPDIR" "$APP_NAME-x86_64.AppImage"
    
    echo ""
    echo "SUCCESS: $APP_NAME-x86_64.AppImage created!"
else
    echo ""
    echo "[!] 'appimagetool' not found."
    echo "To finish creating the AppImage, download it:"
    echo "  wget https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
    echo "  chmod +x appimagetool-x86_64.AppImage"
    echo "  ./compile.sh"
fi

echo ""
echo "Standalone Executable available at: dist/$APP_NAME"
