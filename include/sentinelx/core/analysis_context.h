#pragma once

#include <string>
#include <memory>
#include <optional>

namespace LIEF {
    class Binary;
}

namespace sentinelx {

// Forward declarations
class CallGraphAnalyzer;
class TaintAnalyzer;
class CweRepository;

namespace detectors {
    class IDetector;
}

/**
 * @brief Analysis context provided to detectors
 *
 * This structure provides detectors with access to:
 * - Parsed source code
 * - Binary information (via LIEF)
 * - Call graph
 * - Taint analysis state
 * - CWE database
 * - Configuration
 * - Logger
 */
struct AnalysisContext {
    // Source code analysis
    std::optional<std::string> source_code;         // Full source code (if available)
    std::optional<std::string> file_path;           // Path to file being analyzed

    // Binary analysis
    std::shared_ptr<LIEF::Binary> binary;           // LIEF Binary object (if available)

    // Shared analysis infrastructure
    std::shared_ptr<CallGraphAnalyzer> call_graph;  // Call graph analyzer
    std::shared_ptr<TaintAnalyzer> taint_analyzer;  // Taint analysis

    // CWE database
    std::shared_ptr<CweRepository> cwe_repository;  // CWE database access

    // Configuration
    bool verbose = false;                           // Verbose mode
    bool only_reachable = true;                     // Only report reachable findings

    // Helper methods
    bool has_source() const { return source_code.has_value(); }
    bool has_binary() const { return binary != nullptr; }
    bool has_call_graph() const { return call_graph != nullptr; }
    bool has_taint_analysis() const { return taint_analyzer != nullptr; }
    bool has_cwe_repository() const { return cwe_repository != nullptr; }
};

} // namespace sentinelx
