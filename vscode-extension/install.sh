#!/bin/bash

# SentinelX VS Code Extension Installer
# This script installs or reinstalls the SentinelX extension

set -e

EXTENSION_VSIX="sentinelx-1.0.0.vsix"
EXTENSION_ID="sentinelx.sentinelx"

echo "==================================="
echo "SentinelX Extension Installer"
echo "==================================="
echo ""

# Check if VSIX file exists
if [ ! -f "$EXTENSION_VSIX" ]; then
    echo "Error: $EXTENSION_VSIX not found!"
    echo "Run 'npm run package' first to build the extension."
    exit 1
fi

# Try to find code command
CODE_CMD=""
if command -v code &> /dev/null; then
    CODE_CMD="code"
elif [ -f "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" ]; then
    CODE_CMD="/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
elif [ -f "/Users/gen/Downloads/Visual Studio Code.app/Contents/Resources/app/bin/code" ]; then
    CODE_CMD="/Users/gen/Downloads/Visual Studio Code.app/Contents/Resources/app/bin/code"
else
    echo "Error: VS Code not found"
    echo ""
    echo "Please install VS Code or add it to your PATH"
    exit 1
fi

echo "Using VS Code: $CODE_CMD"

echo "Step 1: Checking for existing installation..."
if "$CODE_CMD" --list-extensions 2>/dev/null | grep -q "^sentinelx"; then
    echo "Found existing installation. Uninstalling..."
    "$CODE_CMD" --uninstall-extension sentinelx.sentinelx 2>/dev/null || true
    echo "Uninstalled successfully"
else
    echo "No existing installation found"
fi

echo ""
echo "Step 2: Installing extension from $EXTENSION_VSIX..."
"$CODE_CMD" --install-extension "$EXTENSION_VSIX" --force

echo ""
echo "Step 3: Verifying installation..."
if "$CODE_CMD" --list-extensions 2>/dev/null | grep -q "^sentinelx"; then
    echo "✓ Extension installed successfully!"
else
    echo "✗ Installation verification failed"
    exit 1
fi

echo ""
echo "==================================="
echo "Installation Complete!"
echo "==================================="
echo ""
echo "Next steps:"
echo "1. Restart VS Code or reload window (Cmd+Shift+P > 'Reload Window')"
echo "2. Open a C/C++ file to activate the extension"
echo "3. Configure SentinelX path in settings if needed:"
echo "   Cmd+Shift+P > 'Preferences: Open Settings' > Search 'sentinelx'"
echo ""
echo "For help, see QUICKSTART.md or INSTALLATION.md"
echo ""
