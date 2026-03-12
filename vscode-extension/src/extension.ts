import * as vscode from 'vscode';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

interface SentinelXFinding {
    file: string;
    line: number;
    function: string;
    kind: string;
    severity: string;
    confidence: string;
    message: string;
}

interface SentinelXReport {
    findings: SentinelXFinding[];
    files_analyzed: number;
}

let diagnosticCollection: vscode.DiagnosticCollection;
let analysisTimeout: NodeJS.Timeout | null = null;
let outputChannel: vscode.OutputChannel;

class SentinelXCodeActionProvider implements vscode.CodeActionProvider {
    public provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range,
        context: vscode.CodeActionContext
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'SentinelX') {
                continue;
            }

            const code = diagnostic.code as string;

            // Quick fixes for integer overflow
            if (code === 'SRC_ARITHMETIC_OVERFLOW') {
                const fix = new vscode.CodeAction(
                    'Use __builtin_mul_overflow for safe multiplication',
                    vscode.CodeActionKind.QuickFix
                );
                fix.diagnostics = [diagnostic];
                fix.isPreferred = true;
                actions.push(fix);

                const fix2 = new vscode.CodeAction(
                    'Add overflow check before operation',
                    vscode.CodeActionKind.QuickFix
                );
                fix2.diagnostics = [diagnostic];
                actions.push(fix2);
            }

            // Quick fixes for unsafe atoi
            if (code?.startsWith('SRC_INTEGER_OVERFLOW_atoi')) {
                const fix = new vscode.CodeAction(
                    'Replace with strtol and errno check',
                    vscode.CodeActionKind.QuickFix
                );
                fix.diagnostics = [diagnostic];
                fix.isPreferred = true;
                actions.push(fix);
            }

            // Quick fixes for malloc overflow
            if (code === 'SRC_ALLOCATION_OVERFLOW' || code === 'SRC_ALLOCATION_CONSTANT_OVERFLOW') {
                const fix = new vscode.CodeAction(
                    'Use calloc instead of malloc',
                    vscode.CodeActionKind.QuickFix
                );
                fix.diagnostics = [diagnostic];
                fix.isPreferred = true;
                actions.push(fix);
            }

            // Quick fixes for buffer overflow
            if (code?.startsWith('SRC_UNSAFE_CALL_strcpy')) {
                const fix = new vscode.CodeAction(
                    'Replace strcpy with strncpy',
                    vscode.CodeActionKind.QuickFix
                );
                fix.diagnostics = [diagnostic];
                fix.isPreferred = true;
                actions.push(fix);
            }

            if (code?.startsWith('SRC_UNSAFE_CALL_strcat')) {
                const fix = new vscode.CodeAction(
                    'Replace strcat with strncat',
                    vscode.CodeActionKind.QuickFix
                );
                fix.diagnostics = [diagnostic];
                fix.isPreferred = true;
                actions.push(fix);
            }

            if (code?.startsWith('SRC_UNSAFE_CALL_sprintf')) {
                const fix = new vscode.CodeAction(
                    'Replace sprintf with snprintf',
                    vscode.CodeActionKind.QuickFix
                );
                fix.diagnostics = [diagnostic];
                fix.isPreferred = true;
                actions.push(fix);
            }

            if (code?.startsWith('SRC_UNSAFE_CALL_gets')) {
                const fix = new vscode.CodeAction(
                    'Replace gets with fgets',
                    vscode.CodeActionKind.QuickFix
                );
                fix.diagnostics = [diagnostic];
                fix.isPreferred = true;
                actions.push(fix);
            }

            // Add documentation link for all vulnerabilities
            const docAction = new vscode.CodeAction(
                '📖 View SentinelX Documentation',
                vscode.CodeActionKind.QuickFix
            );
            docAction.command = {
                title: 'Open Documentation',
                command: 'vscode.open',
                arguments: [vscode.Uri.parse('https://github.com/sentinelx/sentinelx#vulnerabilities')]
            };
            docAction.diagnostics = [diagnostic];
            actions.push(docAction);
        }

        return actions;
    }
}

export function activate(context: vscode.ExtensionContext) {
    console.log('SentinelX extension is now active');

    // Create diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('sentinelx');
    context.subscriptions.push(diagnosticCollection);

    // Create output channel
    outputChannel = vscode.window.createOutputChannel('SentinelX');
    context.subscriptions.push(outputChannel);

    // Register code action provider for quick fixes
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { language: 'c' },
            new SentinelXCodeActionProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );

    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { language: 'cpp' },
            new SentinelXCodeActionProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinelx.analyzeCurrentFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                analyzeFile(editor.document);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinelx.analyzeWorkspace', () => {
            analyzeWorkspace();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinelx.clearDiagnostics', () => {
            diagnosticCollection.clear();
        })
    );

    // Register document save event
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            const config = vscode.workspace.getConfiguration('sentinelx');
            if (config.get<boolean>('analyzeOnSave') && isCOrCppFile(document)) {
                analyzeFile(document);
            }
        })
    );

    // Register document change event (for on-type analysis)
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument((event) => {
            const config = vscode.workspace.getConfiguration('sentinelx');
            if (config.get<boolean>('analyzeOnType') && isCOrCppFile(event.document)) {
                // Debounce analysis
                if (analysisTimeout) {
                    clearTimeout(analysisTimeout);
                }
                const debounceTime = config.get<number>('debounceTime') || 500;
                analysisTimeout = setTimeout(() => {
                    analyzeFile(event.document);
                }, debounceTime);
            }
        })
    );

    // Analyze open files on activation
    if (vscode.window.activeTextEditor) {
        const doc = vscode.window.activeTextEditor.document;
        if (isCOrCppFile(doc)) {
            analyzeFile(doc);
        }
    }
}

function isCOrCppFile(document: vscode.TextDocument): boolean {
    return document.languageId === 'c' || document.languageId === 'cpp';
}

async function analyzeFile(document: vscode.TextDocument): Promise<void> {
    const config = vscode.workspace.getConfiguration('sentinelx');

    if (!config.get<boolean>('enabled')) {
        return;
    }

    const filePath = document.uri.fsPath;
    const execPathConfig = config.get<string>('executablePath');
    const execPath = (execPathConfig && execPathConfig.trim() !== '') ? execPathConfig : 'SentinelX';
    const minConfidence = config.get<string>('minConfidence') || 'MEDIUM';
    const onlyReachable = config.get<boolean>('onlyReachable') ?? true;
    const showUnusedWarnings = config.get<boolean>('showUnusedWarnings') ?? false;

    try {
        outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Analyzing ${path.basename(filePath)}...`);

        // Build command with flags
        let command = `"${execPath}" --source "${filePath}" --json --min-confidence ${minConfidence}`;

        if (onlyReachable) {
            command += ' --only-reachable';
        } else {
            command += ' --all-functions';
        }

        if (showUnusedWarnings) {
            command += ' --show-unused-warnings';
        }

        const { stdout, stderr } = await execAsync(command, {
            cwd: path.dirname(filePath),
            timeout: 30000 // 30 second timeout
        });

        if (stderr) {
            outputChannel.appendLine(`Error: ${stderr}`);
        }

        // Parse JSON output
        let report: SentinelXReport;
        try {
            report = JSON.parse(stdout);
        } catch (parseError) {
            outputChannel.appendLine(`Failed to parse SentinelX output: ${parseError}`);
            return;
        }

        // Clear previous diagnostics for this file
        diagnosticCollection.delete(document.uri);

        // Convert findings to diagnostics
        const diagnostics: vscode.Diagnostic[] = [];
        const showInfo = config.get<boolean>('showInfoSeverity');

        for (const finding of report.findings) {
            // Filter by file
            if (path.normalize(finding.file) !== path.normalize(filePath)) {
                continue;
            }

            // Filter INFO severity if disabled
            if (finding.severity === 'INFO' && !showInfo) {
                continue;
            }

            const line = Math.max(0, finding.line - 1); // Convert to 0-based
            const range = new vscode.Range(line, 0, line, 1000);

            const severity = getSeverity(finding.severity);
            const message = formatMessage(finding);

            const diagnostic = new vscode.Diagnostic(range, message, severity);
            diagnostic.source = 'SentinelX';
            diagnostic.code = finding.kind;

            // Add related information
            if (finding.function) {
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(document.uri, range),
                        `Found in function: ${finding.function}`
                    )
                ];
            }

            diagnostics.push(diagnostic);
        }

        // Set diagnostics
        diagnosticCollection.set(document.uri, diagnostics);

        outputChannel.appendLine(
            `[${new Date().toLocaleTimeString()}] Analysis complete: ${diagnostics.length} issue(s) found`
        );

    } catch (error: any) {
        outputChannel.appendLine(`Analysis failed: ${error.message}`);

        // Check if SentinelX is not found
        if (error.message.includes('command not found') || error.message.includes('ENOENT')) {
            vscode.window.showErrorMessage(
                'SentinelX executable not found. Please configure the path in settings.',
                'Open Settings'
            ).then(choice => {
                if (choice === 'Open Settings') {
                    vscode.commands.executeCommand('workbench.action.openSettings', 'sentinelx.executablePath');
                }
            });
        }
    }
}

async function analyzeWorkspace(): Promise<void> {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }

    const config = vscode.workspace.getConfiguration('sentinelx');
    const execPathConfig = config.get<string>('executablePath');
    const execPath = (execPathConfig && execPathConfig.trim() !== '') ? execPathConfig : 'SentinelX';
    const minConfidence = config.get<string>('minConfidence') || 'MEDIUM';
    const onlyReachable = config.get<boolean>('onlyReachable') ?? true;
    const showUnusedWarnings = config.get<boolean>('showUnusedWarnings') ?? false;

    try {
        outputChannel.show();
        outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Analyzing workspace...`);

        // Build command with flags
        let command = `"${execPath}" --source "${workspaceFolder.uri.fsPath}" --json --min-confidence ${minConfidence}`;

        if (onlyReachable) {
            command += ' --only-reachable';
        } else {
            command += ' --all-functions';
        }

        if (showUnusedWarnings) {
            command += ' --show-unused-warnings';
        }

        const { stdout, stderr } = await execAsync(command, {
            cwd: workspaceFolder.uri.fsPath,
            timeout: 120000 // 2 minute timeout for workspace
        });

        if (stderr) {
            outputChannel.appendLine(`Error: ${stderr}`);
        }

        // Parse JSON output
        let report: SentinelXReport;
        try {
            report = JSON.parse(stdout);
        } catch (parseError) {
            outputChannel.appendLine(`Failed to parse SentinelX output: ${parseError}`);
            return;
        }

        // Clear all diagnostics
        diagnosticCollection.clear();

        // Group findings by file
        const findingsByFile = new Map<string, SentinelXFinding[]>();
        for (const finding of report.findings) {
            const filePath = path.normalize(finding.file);
            if (!findingsByFile.has(filePath)) {
                findingsByFile.set(filePath, []);
            }
            findingsByFile.get(filePath)!.push(finding);
        }

        // Create diagnostics for each file
        const showInfo = config.get<boolean>('showInfoSeverity');

        for (const [filePath, findings] of findingsByFile) {
            const uri = vscode.Uri.file(filePath);
            const diagnostics: vscode.Diagnostic[] = [];

            for (const finding of findings) {
                // Filter INFO severity if disabled
                if (finding.severity === 'INFO' && !showInfo) {
                    continue;
                }

                const line = Math.max(0, finding.line - 1);
                const range = new vscode.Range(line, 0, line, 1000);

                const severity = getSeverity(finding.severity);
                const message = formatMessage(finding);

                const diagnostic = new vscode.Diagnostic(range, message, severity);
                diagnostic.source = 'SentinelX';
                diagnostic.code = finding.kind;

                diagnostics.push(diagnostic);
            }

            diagnosticCollection.set(uri, diagnostics);
        }

        outputChannel.appendLine(
            `[${new Date().toLocaleTimeString()}] Workspace analysis complete: ${report.findings.length} issue(s) found in ${report.files_analyzed} file(s)`
        );

        vscode.window.showInformationMessage(
            `SentinelX: Found ${report.findings.length} issue(s) in ${report.files_analyzed} file(s)`
        );

    } catch (error: any) {
        outputChannel.appendLine(`Workspace analysis failed: ${error.message}`);
        vscode.window.showErrorMessage(`SentinelX analysis failed: ${error.message}`);
    }
}

function getSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity.toUpperCase()) {
        case 'CRITICAL':
            return vscode.DiagnosticSeverity.Error;
        case 'HIGH':
            return vscode.DiagnosticSeverity.Error;
        case 'WARNING':
            return vscode.DiagnosticSeverity.Warning;
        case 'INFO':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Warning;
    }
}

function formatMessage(finding: SentinelXFinding): string {
    let message = `[${finding.severity}][${finding.confidence}] `;

    // Add specific context for different vulnerability types
    switch (finding.kind) {
        case 'SRC_CONSTANT_OVERFLOW':
            message += `⚠️ Integer Overflow (Constants): ${finding.message}`;
            break;
        case 'SRC_ALLOCATION_CONSTANT_OVERFLOW':
            message += `⚠️ Memory Allocation Overflow (Constants): ${finding.message}`;
            break;
        case 'SRC_ARITHMETIC_OVERFLOW':
            message += `⚠️ Arithmetic Overflow (Variables): ${finding.message}`;
            break;
        case 'SRC_ALLOCATION_OVERFLOW':
            message += `⚠️ Memory Allocation Overflow (Variables): ${finding.message}`;
            break;
        case 'SRC_INTEGER_OVERFLOW_atoi':
        case 'SRC_INTEGER_OVERFLOW_atol':
        case 'SRC_INTEGER_OVERFLOW_atoll':
        case 'SRC_INTEGER_OVERFLOW_strtol':
        case 'SRC_INTEGER_OVERFLOW_strtoul':
        case 'SRC_INTEGER_OVERFLOW_strtoll':
        case 'SRC_INTEGER_OVERFLOW_strtoull':
            message += `⚠️ Unsafe String-to-Integer Conversion: ${finding.message}`;
            break;
        case 'SRC_UNSAFE_CALL_strcpy':
        case 'SRC_UNSAFE_CALL_strcat':
        case 'SRC_UNSAFE_CALL_gets':
        case 'SRC_UNSAFE_CALL_sprintf':
        case 'SRC_UNSAFE_CALL_vsprintf':
            message += `🔴 Buffer Overflow Risk: ${finding.message}`;
            break;
        case 'SRC_FORMAT_STRING_VULN':
            message += `🔴 Format String Vulnerability: ${finding.message}`;
            break;
        case 'SRC_COMMAND_INJECTION':
            message += `🔴 Command Injection: ${finding.message}`;
            break;
        case 'SRC_BUFFER_OVERFLOW_MEMCPY':
        case 'SRC_BUFFER_OVERFLOW_READ':
        case 'SRC_BUFFER_OVERFLOW_FGETS':
            message += `🔴 Buffer Overflow: ${finding.message}`;
            break;
        case 'SRC_SCANF_UNBOUNDED':
            message += `⚠️ Unbounded Input: ${finding.message}`;
            break;
        case 'SRC_LARGE_STACK_BUFFER':
            message += `⚠️ Large Stack Allocation: ${finding.message}`;
            break;
        case 'SRC_WRAPPER_CALL':
            message += `⚠️ Unsafe Wrapper Function: ${finding.message}`;
            break;
        default:
            message += finding.message;
    }

    // Add function name if available
    if (finding.function) {
        message += ` (in ${finding.function})`;
    }

    return message;
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
    if (outputChannel) {
        outputChannel.dispose();
    }
    if (analysisTimeout) {
        clearTimeout(analysisTimeout);
    }
}
