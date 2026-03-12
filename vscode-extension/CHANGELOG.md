# Change Log

## [1.0.0] - 2024-12-16

### Initial Release

- Real-time security vulnerability detection for C/C++
- Support for multiple severity levels (CRITICAL, HIGH, WARNING, INFO)
- Confidence-based filtering (LOW, MEDIUM, HIGH, CERTAIN)
- Analyze on save and analyze on type modes
- Workspace-wide analysis
- Visual diagnostics with colored underlines
- Integration with VS Code Problems panel
- Output channel for detailed logs
- Configurable SentinelX executable path
- Debounced on-type analysis for performance

### Detected Vulnerability Types

- Buffer overflows (strcpy, strcat, gets, sprintf, vsprintf)
- Format string vulnerabilities (printf, fprintf)
- Integer overflows
- Stack overflows
- Large stack allocations
- Scanf with unbounded %s
- Fgets buffer mismatches
- Taint analysis for user input tracking
