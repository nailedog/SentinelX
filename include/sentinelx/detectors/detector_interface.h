#pragma once

#include "../core/types.h"
#include "../core/analysis_context.h"
#include "detector_metadata.h"
#include <vector>
#include <string>
#include <memory>

namespace sentinelx {
namespace detectors {

/**
 * @brief Base interface for all vulnerability detectors
 *
 * All detectors (core, plugin, DSL-based) must implement this interface.
 * The interface provides a uniform way to:
 * - Execute analysis
 * - Query metadata
 * - Initialize/shutdown detectors
 */
class IDetector {
public:
    virtual ~IDetector() = default;

    /**
     * @brief Analyze code/binary and return findings
     *
     * This is the main entry point for detection. Detectors receive an
     * AnalysisContext with access to source code, binary, call graph,
     * taint analysis, and other infrastructure.
     *
     * @param context Analysis context with parsed code, config, etc.
     * @return Vector of findings (vulnerabilities detected)
     */
    virtual Findings analyze(const AnalysisContext& context) = 0;

    /**
     * @brief Get detector metadata
     *
     * Returns metadata describing the detector's capabilities, version,
     * supported CWEs, etc.
     *
     * @return Metadata describing the detector
     */
    virtual DetectorMetadata get_metadata() const = 0;

    /**
     * @brief Get supported CWE IDs
     *
     * Returns a list of CWE IDs that this detector can find.
     * This is a convenience wrapper around get_metadata().supported_cwes
     *
     * @return Vector of CWE IDs (e.g., ["CWE-120", "CWE-787"])
     */
    virtual std::vector<std::string> get_supported_cwes() const {
        return get_metadata().supported_cwes;
    }

    /**
     * @brief Initialize detector with configuration (optional)
     *
     * Called once before analysis begins. Detectors can use this to:
     * - Parse configuration
     * - Load resources
     * - Prepare internal state
     *
     * @param config Configuration string (JSON, YAML, etc.)
     */
    virtual void initialize(const std::string& config) {
        // Default: no initialization needed
        (void)config; // Suppress unused parameter warning
    }

    /**
     * @brief Shutdown and cleanup detector (optional)
     *
     * Called once after analysis completes. Detectors can use this to:
     * - Release resources
     * - Cleanup state
     * - Write statistics
     */
    virtual void shutdown() {
        // Default: no shutdown needed
    }

    /**
     * @brief Check if detector can run on this context (optional)
     *
     * Allows detectors to skip analysis if prerequisites aren't met.
     * For example, a source-only detector can return false if no source
     * is available.
     *
     * @param context Analysis context
     * @return true if detector can run, false to skip
     */
    virtual bool can_analyze(const AnalysisContext& context) const {
        const auto& meta = get_metadata();

        // Check if we have required inputs
        if (meta.requires_source && !context.has_source()) {
            return false;
        }
        if (meta.requires_binary && !context.has_binary()) {
            return false;
        }
        if (meta.requires_call_graph && !context.has_call_graph()) {
            return false;
        }
        if (meta.requires_taint_analysis && !context.has_taint_analysis()) {
            return false;
        }

        return true;
    }
};

/**
 * @brief Factory function signature for creating detectors
 *
 * Used by plugin system and detector registry.
 */
using DetectorFactory = std::unique_ptr<IDetector> (*)();

} // namespace detectors
} // namespace sentinelx
