#pragma once

#include <string>
#include <vector>

namespace sentinelx {
namespace detectors {

/**
 * @brief Metadata describing a detector's capabilities and information
 */
struct DetectorMetadata {
    std::string name;                           // Detector name (e.g., "BufferOverflowDetector")
    std::string version;                        // Detector version (e.g., "1.0.0")
    std::string author;                         // Author/organization
    std::string description;                    // Brief description of what it detects

    // Capabilities
    std::vector<std::string> supported_languages;  // e.g., ["C", "C++"]
    bool requires_source = true;                   // Needs source code
    bool requires_binary = false;                  // Needs binary
    bool requires_call_graph = false;              // Needs call graph analysis
    bool requires_taint_analysis = false;          // Needs taint analysis

    // CWE coverage
    std::vector<std::string> supported_cwes;       // CWE IDs this detector can find

    // Performance hints
    bool is_expensive = false;                     // Computationally expensive
    bool supports_parallel = true;                 // Can run in parallel with other detectors
};

} // namespace detectors
} // namespace sentinelx
