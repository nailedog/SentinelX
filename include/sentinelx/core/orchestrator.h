#pragma once

#include "types.h"
#include "analysis_context.h"
#include "../detectors/detector_interface.h"
#include <vector>
#include <string>
#include <memory>
#include <functional>

namespace sentinelx {

/**
 * @brief Analysis orchestrator - coordinates the entire analysis pipeline
 *
 * The orchestrator is responsible for:
 * - Managing detector lifecycle (registration, initialization, execution, shutdown)
 * - Building analysis context (source parsing, binary loading, call graph, etc.)
 * - Coordinating parallel detector execution
 * - Aggregating and enriching findings (CWE info, AI analysis)
 * - Filtering results based on configuration
 */
class AnalysisOrchestrator {
public:
    /**
     * @brief Construct orchestrator with configuration
     * @param config Analysis configuration
     */
    explicit AnalysisOrchestrator(const AnalyzerConfig& config = {});

    /**
     * @brief Destructor - ensures proper cleanup of detectors
     */
    ~AnalysisOrchestrator();

    // Disable copy (manages detector resources)
    AnalysisOrchestrator(const AnalysisOrchestrator&) = delete;
    AnalysisOrchestrator& operator=(const AnalysisOrchestrator&) = delete;

    // Allow move
    AnalysisOrchestrator(AnalysisOrchestrator&&) noexcept;
    AnalysisOrchestrator& operator=(AnalysisOrchestrator&&) noexcept;

    /**
     * @brief Analyze source and binary files
     *
     * Main entry point for analysis. Coordinates:
     * 1. Context building (parse source, load binary, build call graph)
     * 2. Detector execution (parallel when possible)
     * 3. Finding aggregation
     * 4. CWE enrichment
     * 5. AI analysis (if enabled)
     * 6. Filtering
     *
     * @param source_paths Source files to analyze
     * @param binary_paths Binary files to analyze
     * @return Aggregated findings from all detectors
     */
    Findings analyze(const std::vector<std::string>& source_paths,
                    const std::vector<std::string>& binary_paths);

    /**
     * @brief Register a detector
     *
     * Detectors must be registered before analysis begins.
     * The orchestrator takes ownership of the detector.
     *
     * @param detector Unique pointer to detector
     */
    void register_detector(std::unique_ptr<detectors::IDetector> detector);

    /**
     * @brief Load plugins from directory
     *
     * Scans directory for .so/.dll files and loads them as detector plugins.
     *
     * @param plugin_dir Directory containing plugin files
     * @return Number of plugins loaded
     */
    int load_plugins(const std::string& plugin_dir);

    /**
     * @brief Load DSL rules from directory
     *
     * Scans directory for .sxr files and compiles them as detectors.
     *
     * @param rules_dir Directory containing rule files
     * @return Number of rules loaded
     */
    int load_dsl_rules(const std::string& rules_dir);

    /**
     * @brief Get registered detectors
     * @return Vector of detector metadata
     */
    std::vector<detectors::DetectorMetadata> get_registered_detectors() const;

    /**
     * @brief Set progress callback
     *
     * Called during analysis to report progress.
     *
     * @param callback Function called with (current, total, message)
     */
    void set_progress_callback(
        std::function<void(int current, int total, const std::string& message)> callback);

    /**
     * @brief Get configuration
     * @return Current configuration
     */
    const AnalyzerConfig& get_config() const;

    /**
     * @brief Update configuration
     * @param config New configuration
     */
    void set_config(const AnalyzerConfig& config);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sentinelx
