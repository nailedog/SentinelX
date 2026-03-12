#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sentinel {

enum class Severity {
    Info,
    Warning,
    High,
    Critical
};

enum class FindingKind {
    Source,
    Binary
};

struct SourceLocation {
    std::string file;
    std::size_t line = 0;
    std::string context;
    std::string function_name; 
};

struct BinaryLocation {
    std::string  segment_or_section;  // .text, .plt, seg
    std::uint64_t offset = 0;         // virtual address
    std::string  arch;                // x86, x86_64, arm, arm64,
    std::string  disasm;
    std::string  function_name;       // Name of the function where vulnerability was found
    std::uint64_t return_address = 0; // Return address for this location
};

enum class Confidence {
    Low,      // Likely false positive, needs manual review
    Medium,   // Possibly vulnerable, review recommended
    High,     // Very likely vulnerable
    Certain   // Definitely vulnerable (e.g., gets(), hardcoded dangerous patterns)
};

struct Finding {
    FindingKind     kind        = FindingKind::Source;
    Severity        severity    = Severity::Info;
    Confidence      confidence  = Confidence::Medium;  // Default confidence level
    std::string     id;
    std::string     message;
    std::string     recommendation;
    SourceLocation  source_location;
    BinaryLocation  binary_location;
    bool            is_in_reachable_function = true;  // Is this finding in a function reachable from main?
};

struct AnalyzerConfig {
    bool analyze_source = true;
    bool analyze_binary = true;
    bool verbose        = false;
    Confidence min_confidence = Confidence::Low;  // Minimum confidence level to report
    bool only_reachable_functions = true;  // Only report vulnerabilities in functions called from main/entry points
    bool show_unused_function_warnings = false;  // Show warnings for unused functions with vulnerabilities
};

using Findings = std::vector<Finding>;

inline std::string severity_to_string(Severity s) {
    switch (s) {
        case Severity::Info:     return "INFO";
        case Severity::Warning:  return "WARNING";
        case Severity::High:     return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

inline std::string kind_to_string(FindingKind k) {
    switch (k) {
        case FindingKind::Source: return "SOURCE";
        case FindingKind::Binary: return "BINARY";
    }
    return "UNKNOWN";
}

inline std::string confidence_to_string(Confidence c) {
    switch (c) {
        case Confidence::Low:     return "LOW";
        case Confidence::Medium:  return "MEDIUM";
        case Confidence::High:    return "HIGH";
        case Confidence::Certain: return "CERTAIN";
    }
    return "UNKNOWN";
}

}
