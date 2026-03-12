#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace sentinelx {

// Re-export core types from legacy namespace for compatibility
enum class Severity {
    Info,
    Warning,
    High,
    Critical
};

enum class Confidence {
    Low,      // Likely false positive, needs manual review
    Medium,   // Possibly vulnerable, review recommended
    High,     // Very likely vulnerable
    Certain   // Definitely vulnerable (e.g., gets(), hardcoded dangerous patterns)
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
    std::string  arch;                // x86, x86_64, arm, arm64
    std::string  disasm;
    std::string  function_name;       // Name of the function where vulnerability was found
    std::uint64_t return_address = 0; // Return address for this location
};

// Enhanced Finding structure with CWE support and AI metadata
struct Finding {
    // Core identification
    FindingKind     kind        = FindingKind::Source;
    Severity        severity    = Severity::Info;
    Confidence      confidence  = Confidence::Medium;
    std::string     id;          // e.g., "SRC_UNSAFE_CALL_gets"
    std::string     message;
    std::string     recommendation;

    // Location information
    SourceLocation  source_location;
    BinaryLocation  binary_location;

    // Reachability
    bool            is_in_reachable_function = true;

    // CWE integration (new)
    std::optional<std::string> cwe_id;           // e.g., "CWE-120"
    std::optional<std::string> cwe_name;         // e.g., "Buffer Copy without Checking Size"

    // AI metadata (new)
    std::optional<std::string> ai_explanation;   // AI-generated explanation
    std::optional<std::string> ai_exploit_hints; // AI-suggested exploitation approach
    float ai_confidence_adjustment = 0.0f;       // AI confidence delta (-1.0 to +1.0)

    // Detector metadata (new)
    std::string detector_name;                   // Which detector found this
    std::string detector_version;                // Detector version
};

using Findings = std::vector<Finding>;

// Analysis configuration
struct AnalyzerConfig {
    // Legacy options
    bool analyze_source = true;
    bool analyze_binary = true;
    bool verbose        = false;
    Confidence min_confidence = Confidence::Low;
    bool only_reachable_functions = true;
    bool show_unused_function_warnings = false;

    // Plugin options (new)
    std::string plugin_dir;                      // Directory to load plugins from
    bool enable_plugins = true;                  // Enable plugin system
    std::vector<std::string> disabled_plugins;   // Plugins to disable

    // DSL options (new)
    std::string rules_dir;                       // Directory to load DSL rules from
    bool enable_dsl_rules = true;                // Enable DSL rule system

    // AI options (new)
    bool enable_ai = false;                      // Enable AI-powered analysis
    bool enable_local_ml = false;                // Enable local ML models
    bool enable_llm = false;                     // Enable LLM API integration
    std::string llm_provider;                    // "openai", "anthropic", etc.
    std::string llm_api_key;                     // API key for LLM

    // CWE options (new)
    std::string cwe_database_path;               // Path to CWE SQLite database
    bool enrich_with_cwe = true;                 // Automatically add CWE info to findings
};

// Helper functions
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

// Convert string to severity
inline Severity string_to_severity(const std::string& s) {
    if (s == "INFO") return Severity::Info;
    if (s == "WARNING") return Severity::Warning;
    if (s == "HIGH") return Severity::High;
    if (s == "CRITICAL") return Severity::Critical;
    return Severity::Info;
}

// Convert string to confidence
inline Confidence string_to_confidence(const std::string& s) {
    if (s == "LOW") return Confidence::Low;
    if (s == "MEDIUM") return Confidence::Medium;
    if (s == "HIGH") return Confidence::High;
    if (s == "CERTAIN") return Confidence::Certain;
    return Confidence::Medium;
}

} // namespace sentinelx
