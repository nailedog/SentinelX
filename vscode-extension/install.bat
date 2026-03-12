@echo off
REM SentinelX VS Code Extension Installer for Windows

setlocal

set EXTENSION_VSIX=sentinelx-1.0.0.vsix

echo ===================================
echo SentinelX Extension Installer
echo ===================================
echo.

REM Check if VSIX file exists
if not exist "%EXTENSION_VSIX%" (
    echo Error: %EXTENSION_VSIX% not found!
    echo Run 'npm run package' first to build the extension.
    exit /b 1
)

REM Check if code command exists
where code >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: 'code' command not found in PATH
    echo.
    echo Please add VS Code to your PATH:
    echo 1. Open VS Code
    echo 2. Press Ctrl+Shift+P
    echo 3. Type 'Shell Command: Install code command in PATH'
    echo 4. Run this script again
    exit /b 1
)

echo Step 1: Checking for existing installation...
code --list-extensions 2>nul | findstr /C:"sentinelx" >nul
if %errorlevel% equ 0 (
    echo Found existing installation. Uninstalling...
    code --uninstall-extension sentinelx.sentinelx >nul 2>&1
    echo Uninstalled successfully
) else (
    echo No existing installation found
)

echo.
echo Step 2: Installing extension from %EXTENSION_VSIX%...
code --install-extension "%EXTENSION_VSIX%" --force

echo.
echo Step 3: Verifying installation...
code --list-extensions 2>nul | findstr /C:"sentinelx" >nul
if %errorlevel% equ 0 (
    echo √ Extension installed successfully!
) else (
    echo × Installation verification failed
    exit /b 1
)

echo.
echo ===================================
echo Installation Complete!
echo ===================================
echo.
echo Next steps:
echo 1. Restart VS Code or reload window (Ctrl+Shift+P ^> 'Reload Window'^)
echo 2. Open a C/C++ file to activate the extension
echo 3. Configure SentinelX path in settings if needed:
echo    Ctrl+Shift+P ^> 'Preferences: Open Settings' ^> Search 'sentinelx'
echo.
echo For help, see QUICKSTART.md or INSTALLATION.md
echo.

endlocal
