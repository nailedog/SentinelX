#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>
#include <sstream>
#include <iomanip>

#include "analyzer.h"
#include "types.h"
#include "report.hpp"
#include "json_output.hpp"
#include "exploit_engine.h"
#include "disassembler.h"
#include "binary_parser.h"

using sentinel::Analyzer;
using sentinel::AnalyzerConfig;
using sentinel::Finding;
using sentinel::Findings;
using sentinel::FindingKind;
using sentinel::Severity;
using sentinel::Confidence;

namespace {

void print_usage(const char* prog) {
    std::cout
        << "Usage:\n"
        << "  " << prog << " [options]\n\n"
        << "Options:\n"
        << "  --source <PATH>       Add source file or directory for analysis\n"
        << "  --binary <PATH>       Add binary file for analysis\n"
        << "  --no-source           Disable source analysis\n"
        << "  --no-binary           Disable binary analysis\n"
        << "  --verbose             Show INFO-level messages\n"
        << "  --json                Output findings as JSON report\n"
        << "  --min-confidence <LEVEL>  Minimum confidence level to report\n"
        << "                        (LOW, MEDIUM, HIGH, CERTAIN)\n"
        << "                        Default: LOW (show all findings)\n"
        << "\nFunction Reachability Filtering:\n"
        << "  --only-reachable      Only show vulnerabilities in functions reachable from main (default)\n"
        << "  --all-functions       Show all vulnerabilities\n"
        << "  --show-unused-warnings  Show warnings for unused functions with vulnerabilities\n"
        << "\nExploit Generation:\n"
        << "  --generate-exploits   Enable exploit generation for vulnerabilities\n"
        << "  --exploit-format <FMT>  Exploit format: python, c, both (default: python)\n"
        << "  --exploit-output <DIR>  Output directory for exploits (default: ./exploits)\n"
        << "  --no-shellcode        Disable shellcode generation\n"
        << "  --no-rop              Disable ROP chain generation\n"
        << "\nDisassembly:\n"
        << "  --disas <FUNCTION>    Disassemble function and highlight dangerous instructions\n"
        << "  --interactive         Enter interactive mode for disassembly commands\n"
        << "\n"
        << "  -h, --help            Show this help\n\n"
        << "Examples:\n"
        << "  " << prog << " --source ./test --binary ./a.out\n"
        << "  " << prog << " --source ./src --min-confidence HIGH\n"
        << "  " << prog << " --source ./src --all-functions  # Show all functions (including unused)\n"
        << "  " << prog << " --binary ./vuln --generate-exploits --exploit-format both\n";
}

sx::AnalysisReport build_report(const Findings& findings) {
    sx::AnalysisReport report;

    std::unordered_set<std::string> files;

    for (const auto& f : findings) {
        sx::Finding rf;

        if (!f.source_location.file.empty()) {
            rf.file = f.source_location.file;
            rf.line = static_cast<int>(f.source_location.line);
            files.insert(f.source_location.file);
        } else if (!f.binary_location.segment_or_section.empty()) {
            rf.file = f.binary_location.segment_or_section;
            rf.line = 0;
        } else {
            rf.file = "";
            rf.line = 0;
        }

        if (!f.source_location.file.empty()) {
            rf.function = f.source_location.function_name;
        } else if (!f.binary_location.arch.empty()) {
            rf.function = f.binary_location.function_name;
        } else {
            rf.function = "";
        }
        rf.buffer   = ""; // furures...

        if (f.binary_location.return_address != 0) {
            std::ostringstream oss;
            oss << "0x" << std::hex << f.binary_location.return_address;
            rf.return_address = oss.str();
        } else {
            rf.return_address = "";
        }

        rf.kind     = f.id;
        rf.severity = sentinel::severity_to_string(f.severity);
        rf.confidence = sentinel::confidence_to_string(f.confidence);
        rf.message  = f.message;

        report.findings.push_back(std::move(rf));
    }

    report.files_analyzed = files.size();
    return report;
}

void run_interactive_mode(const std::string& binary_path) {
    sentinel::Disassembler disasm;
    sentinel::BinaryParser parser;
    sentinel::BinaryInfo binary_info;

    std::cout << "Loading binary: " << binary_path << "\n";

    try {
        disasm.load_binary(binary_path);
        binary_info = parser.parse(binary_path);
        std::cout << "Binary loaded successfully.\n";
        std::cout << "Architecture: " << binary_info.arch << "\n";
        std::cout << "Found " << binary_info.functions.size() << " functions.\n\n";
    } catch (const std::exception& e) {
        std::cerr << "Error loading binary: " << e.what() << "\n";
        return;
    }

    std::cout << "Interactive disassembly mode. Type 'help' for available commands.\n";

    while (true) {
        std::cout << "(sentinelx) ";
        std::string line;
        if (!std::getline(std::cin, line)) {
            break;
        }

        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        if (line.empty()) {
            continue;
        }

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "quit" || cmd == "q" || cmd == "exit") {
            break;
        } else if (cmd == "help" || cmd == "h") {
            std::cout << "Available commands:\n"
                      << "  disas <function>     - Disassemble function with highlighted dangerous instructions\n"
                      << "  info functions       - List all functions in the binary\n"
                      << "  help                 - Show this help\n"
                      << "  quit                 - Exit interactive mode\n";
        } else if (cmd == "info") {
            std::string subcmd;
            iss >> subcmd;
            if (subcmd == "functions") {
                std::cout << "Functions in binary:\n";
                for (const auto& func : binary_info.functions) {
                    std::cout << "  0x" << std::hex << std::setw(8) << std::setfill('0')
                              << func.address << std::dec << "  " << func.name;
                    if (func.size > 0) {
                        std::cout << " (size: " << func.size << " bytes)";
                    }
                    std::cout << "\n";
                }
            } else {
                std::cout << "Unknown info command. Try 'info functions'\n";
            }
        } else if (cmd == "disas") {
            std::string func_name;
            iss >> func_name;
            if (func_name.empty()) {
                std::cout << "Usage: disas <function_name>\n";
                continue;
            }

            std::cout << "Disassembling function: " << func_name << "\n\n";

            try {
                auto instructions = disasm.disassemble_function(binary_info, func_name);
                if (instructions.empty()) {
                    std::cout << "Function not found or could not be disassembled.\n";
                } else {
                    std::string formatted = disasm.format_disassembly(instructions, true, false);
                    std::cout << formatted;

                    // Count dangerous instructions
                    int dangerous_count = 0;
                    for (const auto& inst : instructions) {
                        if (disasm.is_dangerous_instruction(inst)) {
                            dangerous_count++;
                        }
                    }
                    std::cout << "\nTotal instructions: " << instructions.size() << "\n";
                    std::cout << "Dangerous instructions: " << dangerous_count << " [!]\n";
                }
            } catch (const std::exception& e) {
                std::cout << "Error disassembling function: " << e.what() << "\n";
            }
        } else {
            std::cout << "Unknown command: " << cmd << ". Type 'help' for available commands.\n";
        }
    }

    std::cout << "Exiting interactive mode.\n";
}

}

int main(int argc, char** argv) {
    AnalyzerConfig config;
    std::vector<std::string> source_paths;
    std::vector<std::string> binary_paths;
    bool json_output = false;

    bool generate_exploits = false;
    sentinel::exploit::ExploitConfig exploit_config;

    // Disassembly options
    bool interactive_mode = false;
    std::string disas_function;
    bool disas_requested = false;

    if (argc == 1) {
        print_usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--source") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --source\n";
                return 1;
            }
            source_paths.emplace_back(argv[++i]);
        } else if (arg == "--binary") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --binary\n";
                return 1;
            }
            binary_paths.emplace_back(argv[++i]);
        } else if (arg == "--no-source") {
            config.analyze_source = false;
        } else if (arg == "--no-binary") {
            config.analyze_binary = false;
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--json") {
            json_output = true;
        } else if (arg == "--min-confidence") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --min-confidence\n";
                return 1;
            }
            std::string conf_str = argv[++i];
            if (conf_str == "LOW") {
                config.min_confidence = sentinel::Confidence::Low;
            } else if (conf_str == "MEDIUM") {
                config.min_confidence = sentinel::Confidence::Medium;
            } else if (conf_str == "HIGH") {
                config.min_confidence = sentinel::Confidence::High;
            } else if (conf_str == "CERTAIN") {
                config.min_confidence = sentinel::Confidence::Certain;
            } else {
                std::cerr << "Invalid confidence level: " << conf_str << "\n";
                std::cerr << "Valid values: LOW, MEDIUM, HIGH, CERTAIN\n";
                return 1;
            }
        } else if (arg == "--generate-exploits") {
            generate_exploits = true;
        } else if (arg == "--exploit-format") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --exploit-format\n";
                return 1;
            }
            std::string fmt = argv[++i];
            if (fmt == "python") {
                exploit_config.format = sentinel::exploit::ExploitFormat::PYTHON;
            } else if (fmt == "c") {
                exploit_config.format = sentinel::exploit::ExploitFormat::C;
            } else if (fmt == "both") {
                exploit_config.format = sentinel::exploit::ExploitFormat::BOTH;
            } else {
                std::cerr << "Invalid exploit format: " << fmt << "\n";
                std::cerr << "Valid values: python, c, both\n";
                return 1;
            }
        } else if (arg == "--exploit-output") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --exploit-output\n";
                return 1;
            }
            exploit_config.output_dir = argv[++i];
        } else if (arg == "--no-shellcode") {
            exploit_config.include_shellcode = false;
        } else if (arg == "--no-rop") {
            exploit_config.include_rop = false;
        } else if (arg == "--only-reachable") {
            config.only_reachable_functions = true;
        } else if (arg == "--all-functions") {
            config.only_reachable_functions = false;
        } else if (arg == "--show-unused-warnings") {
            config.show_unused_function_warnings = true;
        } else if (arg == "--disas") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --disas\n";
                return 1;
            }
            disas_function = argv[++i];
            disas_requested = true;
        } else if (arg == "--interactive") {
            interactive_mode = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Handle interactive mode
    if (interactive_mode) {
        if (binary_paths.empty()) {
            std::cerr << "Interactive mode requires a binary file (--binary <path>).\n";
            return 1;
        }
        run_interactive_mode(binary_paths[0]);
        return 0;
    }

    // Handle --disas flag
    if (disas_requested) {
        if (binary_paths.empty()) {
            std::cerr << "Disassembly requires a binary file (--binary <path>).\n";
            return 1;
        }

        sentinel::Disassembler disasm;
        sentinel::BinaryParser parser;

        try {
            disasm.load_binary(binary_paths[0]);
            sentinel::BinaryInfo binary_info = parser.parse(binary_paths[0]);

            std::cout << "Disassembling function: " << disas_function << "\n\n";

            auto instructions = disasm.disassemble_function(binary_info, disas_function);
            if (instructions.empty()) {
                std::cout << "Function not found or could not be disassembled.\n";
                return 1;
            }

            std::string formatted = disasm.format_disassembly(instructions, true, false);
            std::cout << formatted;

            // Count dangerous instructions
            int dangerous_count = 0;
            for (const auto& inst : instructions) {
                if (disasm.is_dangerous_instruction(inst)) {
                    dangerous_count++;
                }
            }
            std::cout << "\nTotal instructions: " << instructions.size() << "\n";
            std::cout << "Dangerous instructions: " << dangerous_count << " [!]\n";
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            return 1;
        }

        return 0;
    }

    if (!config.analyze_source && !config.analyze_binary) {
        std::cerr << "Both source and binary analysis are disabled.\n";
        return 1;
    }

    if (source_paths.empty() && binary_paths.empty()) {
        std::cerr << "No input paths specified (neither --source nor --binary).\n";
        print_usage(argv[0]);
        return 1;
    }

    Analyzer analyzer(config);
    Findings findings = analyzer.analyze(source_paths, binary_paths);

    if (json_output) {
        sx::AnalysisReport report = build_report(findings);
        sx::print_json(report, std::cout);
        return 0;
    }

    if (findings.empty()) {
        std::cout << "No potential buffer overflows detected.\n";
        return 0;
    }

    std::size_t printed = 0;
    for (const Finding& f : findings) {
        if (!config.verbose && f.severity == Severity::Info) {
            continue;
        }

        // Filter by confidence level
        if (f.confidence < config.min_confidence) {
            continue;
        }

        ++printed;
        std::cout << "[" << sentinel::kind_to_string(f.kind) << "]"
                  << "[" << sentinel::severity_to_string(f.severity) << "]"
                  << "[Confidence: " << sentinel::confidence_to_string(f.confidence) << "] "
                  << f.id << "\n";

        if (!f.source_location.file.empty()) {
            std::cout << "  at " << f.source_location.file
                      << ":" << f.source_location.line;
            if (!f.source_location.function_name.empty()) {
                std::cout << " in function '" << f.source_location.function_name << "'";
            }
            std::cout << "\n";

            if (!f.source_location.context.empty()) {
                std::cout << "  Source context:\n";
                std::cout << f.source_location.context;
            }
        } else if (!f.binary_location.arch.empty()) {
            std::cout << "  arch: " << f.binary_location.arch;
            if (!f.binary_location.segment_or_section.empty()) {
                std::cout << ", section: " << f.binary_location.segment_or_section;
            }
            if (f.binary_location.offset != 0) {
                std::cout << ", offset: 0x"
                          << std::hex << f.binary_location.offset << std::dec;
            }
            if (!f.binary_location.function_name.empty()) {
                std::cout << ", function: " << f.binary_location.function_name;
            }
            if (f.binary_location.return_address != 0) {
                std::cout << ", return_addr: 0x"
                          << std::hex << f.binary_location.return_address << std::dec;
            }
            std::cout << "\n";

            if (!f.binary_location.disasm.empty()) {
                std::cout << "  Disassembly:\n";
                std::cout << f.binary_location.disasm << "\n";
            }
        }

        if (!f.message.empty()) {
            std::cout << "  " << f.message << "\n";
        }
        if (!f.recommendation.empty()) {
            std::cout << "  Recommendation: " << f.recommendation << "\n";
        }
        std::cout << "\n";
    }

    if (printed == 0) {
        std::cout << "No findings (after filtering INFO-level messages).\n";
    }

    if (generate_exploits && !findings.empty() && !binary_paths.empty()) {
        std::cout << "\n[*] Generating exploits...\n";

        sentinel::exploit::ExploitEngine exploit_engine;

        for (const auto& finding : findings) {
            if (finding.severity >= sentinel::Severity::Warning &&
                finding.kind == sentinel::FindingKind::Binary &&
                finding.binary_location.arch != "") {

                sentinel::exploit::BinaryInfo binary_info;
                binary_info.path = !binary_paths.empty() ? binary_paths[0] : "";

                if (finding.binary_location.arch == "x86_64" || finding.binary_location.arch == "amd64") {
                    binary_info.arch = sentinel::exploit::Architecture::X86_64;
                    binary_info.is_64bit = true;
                } else if (finding.binary_location.arch == "x86" || finding.binary_location.arch == "i386") {
                    binary_info.arch = sentinel::exploit::Architecture::X86;
                    binary_info.is_64bit = false;
                } else if (finding.binary_location.arch == "arm") {
                    binary_info.arch = sentinel::exploit::Architecture::ARM;
                    binary_info.is_64bit = false;
                } else if (finding.binary_location.arch == "aarch64" || finding.binary_location.arch == "arm64") {
                    binary_info.arch = sentinel::exploit::Architecture::ARM64;
                    binary_info.is_64bit = true;
                }

                try {
                    auto files = exploit_engine.generate_and_save_exploits(
                        finding,
                        binary_info,
                        exploit_config
                    );

                    if (files.empty()) {
                        std::cout << "[!] Could not generate exploit for " << finding.id << "\n";
                    }
                } catch (const std::exception& e) {
                    std::cerr << "[!] Exploit generation failed: " << e.what() << "\n";
                }
            }
        }

        std::cout << "[*] Exploit generation complete.\n";
    }

    return 0;
}
