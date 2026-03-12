# SentinelX VS Code Extension

Real-time C/C++ security vulnerability detection powered by SentinelX analyzer.

## Features

- **Real-time Analysis**: Detect vulnerabilities as you type or when you save files
- **Visual Indicators**: Underline vulnerable code with yellow/red squiggles
- **Detailed Diagnostics**: Hover over issues to see detailed information
- **Multiple Severity Levels**: CRITICAL, HIGH, WARNING, INFO
- **Confidence Levels**: Filter findings by confidence (LOW, MEDIUM, HIGH, CERTAIN)
- **Workspace Analysis**: Scan entire workspace for vulnerabilities

## Detected Vulnerabilities

- Buffer overflows (strcpy, strcat, gets, sprintf, etc.)
- Format string vulnerabilities (printf, fprintf with non-literal format)
- Integer overflows
- Stack overflows
- Taint analysis (tracking user input flow)

## Requirements

- SentinelX executable must be installed and accessible
- C/C++ files in your workspace

## Installation

### 1. Install SentinelX

First, build the SentinelX analyzer:

```bash
cd /path/to/SentinelX
./build.sh
```

### 2. Install VS Code Extension

#### Option A: From VSIX (Recommended)

```bash
cd vscode-extension
npm install
npm run compile
npm run package
code --install-extension sentinelx-1.0.0.vsix
```

#### Option B: Development Mode

1. Open `vscode-extension` folder in VS Code
2. Press F5 to launch Extension Development Host
3. Test the extension in the new VS Code window

### 3. Configure Extension

Open VS Code Settings (Cmd+, or Ctrl+,) and search for "sentinelx":

```json
{
  "sentinelx.enabled": true,
  "sentinelx.executablePath": "/path/to/SentinelX/build/SentinelX",
  "sentinelx.analyzeOnSave": true,
  "sentinelx.analyzeOnType": false,
  "sentinelx.minConfidence": "MEDIUM"
}
```

## Usage

### Automatic Analysis

- **On Save**: Analysis runs automatically when you save a C/C++ file (if enabled)
- **On Type**: Analysis runs while typing (if enabled, with debouncing)

### Manual Analysis

- **Current File**: `Cmd+Shift+P` → "SentinelX: Analyze Current File"
- **Workspace**: `Cmd+Shift+P` → "SentinelX: Analyze Whole Workspace"
- **Clear**: `Cmd+Shift+P` → "SentinelX: Clear All Diagnostics"

### Reading Diagnostics

Vulnerable code will be underlined:
- **Red squiggly**: CRITICAL/HIGH severity
- **Yellow squiggly**: WARNING severity
- **Blue squiggly**: INFO severity

Hover over the underlined code to see:
- Vulnerability type
- Severity and confidence level
- Detailed message
- Function name where vulnerability was found

## Configuration

### Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `sentinelx.enabled` | boolean | `true` | Enable/disable the extension |
| `sentinelx.executablePath` | string | `""` | Path to SentinelX executable |
| `sentinelx.analyzeOnSave` | boolean | `true` | Run analysis on file save |
| `sentinelx.analyzeOnType` | boolean | `false` | Run analysis while typing |
| `sentinelx.minConfidence` | string | `"MEDIUM"` | Minimum confidence level (LOW/MEDIUM/HIGH/CERTAIN) |
| `sentinelx.showInfoSeverity` | boolean | `false` | Show INFO severity findings |
| `sentinelx.debounceTime` | number | `500` | Debounce time for on-type analysis (ms) |

### Example Configuration

For **maximum security** (strict mode):
```json
{
  "sentinelx.minConfidence": "MEDIUM",
  "sentinelx.showInfoSeverity": true,
  "sentinelx.analyzeOnSave": true
}
```

For **performance** (less intrusive):
```json
{
  "sentinelx.minConfidence": "HIGH",
  "sentinelx.showInfoSeverity": false,
  "sentinelx.analyzeOnType": false
}
```

For **real-time development** (aggressive):
```json
{
  "sentinelx.analyzeOnType": true,
  "sentinelx.debounceTime": 1000,
  "sentinelx.minConfidence": "MEDIUM"
}
```

SentinelX will show:
```
[CRITICAL][HIGH] Call to potentially unsafe function 'strcpy' without explicit bounds. (in authenticate)
```

## Troubleshooting

### "SentinelX executable not found"

- Ensure SentinelX is built: `cd /path/to/SentinelX && ./build.sh`
- Configure the path: `sentinelx.executablePath` in settings
- Or add SentinelX to your PATH

### No diagnostics appearing

- Check Output panel: View → Output → Select "SentinelX"
- Verify file is C/C++: Check language mode in bottom-right corner
- Ensure `sentinelx.enabled` is `true`
- Try manual analysis: "SentinelX: Analyze Current File"

### Performance issues with analyzeOnType

- Increase `sentinelx.debounceTime` (e.g., 1000ms or 2000ms)
- Or disable `sentinelx.analyzeOnType` and use `analyzeOnSave` only
- Increase `minConfidence` to reduce false positives

## Contributing

Issues and pull requests are welcome at: https://github.com/yourusername/sentinelx

## License

Educational project for security research and vulnerability analysis.

## Disclaimer

This tool is for authorized security testing and educational purposes only. Always obtain permission before testing systems you don't own.
