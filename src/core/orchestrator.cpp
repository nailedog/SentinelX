#include "../../include/sentinelx/core/orchestrator.h"
#include "../../include/sentinelx/cwe/cwe_repository.h"
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <thread>
#include <mutex>

namespace sentinelx {

// =============================================================================
// AnalysisOrchestrator::Impl - Private implementation
// =============================================================================
class AnalysisOrchestrator::Impl {
public:
    AnalyzerConfig config;
    std::vector<std::unique_ptr<detectors::IDetector>> detectors;
    std::shared_ptr<CweRepository> cwe_repo;
    std::function<void(int, int, const std::string&)> progress_callback;
    std::mutex findings_mutex;  // For thread-safe finding aggregation

    explicit Impl(const AnalyzerConfig& cfg) : config(cfg) {
        // Initialize CWE repository if path is provided
        if (!config.cwe_database_path.empty()) {
            try {
                cwe_repo = std::make_shared<CweRepository>(config.cwe_database_path);

                // Check if database needs initialization
                if (cwe_repo->get_cwe_count() == 0) {
                    if (config.verbose) {
                        std::cout << "Initializing CWE database..." << std::endl;
                    }
                    // Assuming schema is in same directory as database
                    std::filesystem::path db_path(config.cwe_database_path);
                    std::filesystem::path schema_path = db_path.parent_path() / "../cwe/cwe_schema.sql";

                    if (std::filesystem::exists(schema_path)) {
                        cwe_repo->initialize_database(schema_path.string());
                    }
                }

                if (config.verbose) {
                    std::cout << "CWE database loaded: "
                              << cwe_repo->get_cwe_count() << " entries" << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "Warning: Failed to load CWE database: " << e.what() << std::endl;
                cwe_repo = nullptr;
            }
        }
    }

    // Build analysis context for a file
    AnalysisContext build_context(const std::string& source_path) {
        AnalysisContext ctx;

        // Load source code
        if (!source_path.empty() && std::filesystem::exists(source_path)) {
            std::ifstream file(source_path);
            if (file) {
                std::stringstream buffer;
                buffer << file.rdbuf();
                ctx.source_code = buffer.str();
                ctx.file_path = source_path;
            }
        }

        // Set configuration
        ctx.verbose = config.verbose;
        ctx.only_reachable = config.only_reachable_functions;

        // Set CWE repository
        ctx.cwe_repository = cwe_repo;

        // TODO: Add call graph, taint analysis when implemented

        return ctx;
    }

    // Enrich finding with CWE information
    void enrich_with_cwe(Finding& finding) {
        if (!cwe_repo || !config.enrich_with_cwe) {
            return;
        }

        // Try to map vulnerability ID to CWE
        if (finding.cwe_id.has_value()) {
            // Already has CWE ID, fetch info
            auto cwe_info = cwe_repo->get_cwe_info(finding.cwe_id.value());
            if (cwe_info.has_value()) {
                finding.cwe_name = cwe_info->name;
            }
        } else {
            // Try to map from vulnerability ID
            auto cwe_id = cwe_repo->map_vuln_to_cwe(finding.id);
            if (cwe_id.has_value()) {
                finding.cwe_id = cwe_id.value();

                auto cwe_info = cwe_repo->get_cwe_info(cwe_id.value());
                if (cwe_info.has_value()) {
                    finding.cwe_name = cwe_info->name;
                }
            }
        }
    }

    // Filter findings based on configuration
    bool should_include_finding(const Finding& finding) const {
        // Filter by confidence
        if (finding.confidence < config.min_confidence) {
            return false;
        }

        // Filter by reachability
        if (config.only_reachable_functions && !finding.is_in_reachable_function) {
            if (!config.show_unused_function_warnings) {
                return false;
            }
        }

        return true;
    }

    // Report progress
    void report_progress(int current, int total, const std::string& message) {
        if (progress_callback) {
            progress_callback(current, total, message);
        } else if (config.verbose) {
            std::cout << "[" << current << "/" << total << "] " << message << std::endl;
        }
    }
};

// =============================================================================
// AnalysisOrchestrator Implementation
// =============================================================================

AnalysisOrchestrator::AnalysisOrchestrator(const AnalyzerConfig& config)
    : impl_(std::make_unique<Impl>(config)) {
}

AnalysisOrchestrator::~AnalysisOrchestrator() {
    // Shutdown all detectors
    for (auto& detector : impl_->detectors) {
        try {
            detector->shutdown();
        } catch (const std::exception& e) {
            std::cerr << "Warning: Detector shutdown failed: " << e.what() << std::endl;
        }
    }
}

AnalysisOrchestrator::AnalysisOrchestrator(AnalysisOrchestrator&&) noexcept = default;
AnalysisOrchestrator& AnalysisOrchestrator::operator=(AnalysisOrchestrator&&) noexcept = default;

Findings AnalysisOrchestrator::analyze(
    const std::vector<std::string>& source_paths,
    const std::vector<std::string>& binary_paths) {

    Findings all_findings;

    // Initialize all detectors
    impl_->report_progress(0, 100, "Initializing detectors");
    for (auto& detector : impl_->detectors) {
        try {
            detector->initialize("");  // TODO: Pass detector-specific config
        } catch (const std::exception& e) {
            std::cerr << "Warning: Detector initialization failed: " << e.what() << std::endl;
        }
    }

    // Analyze source files
    if (impl_->config.analyze_source && !source_paths.empty()) {
        impl_->report_progress(10, 100, "Analyzing source files");

        int file_idx = 0;
        for (const auto& source_path : source_paths) {
            file_idx++;

            if (impl_->config.verbose) {
                std::cout << "Analyzing: " << source_path << std::endl;
            }

            // Build context for this file
            AnalysisContext ctx = impl_->build_context(source_path);

            // Run all applicable detectors
            int detector_idx = 0;
            for (auto& detector : impl_->detectors) {
                detector_idx++;

                // Check if detector can analyze this context
                if (!detector->can_analyze(ctx)) {
                    continue;
                }

                try {
                    // Run detector
                    auto metadata = detector->get_metadata();
                    impl_->report_progress(
                        10 + (file_idx * 40) / source_paths.size(),
                        100,
                        "Running " + metadata.name + " on " + source_path
                    );

                    Findings findings = detector->analyze(ctx);

                    // Add detector metadata to findings
                    for (auto& finding : findings) {
                        finding.detector_name = metadata.name;
                        finding.detector_version = metadata.version;

                        // Enrich with CWE info
                        impl_->enrich_with_cwe(finding);

                        // Filter
                        if (impl_->should_include_finding(finding)) {
                            all_findings.push_back(finding);
                        }
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Warning: Detector failed: " << e.what() << std::endl;
                }
            }
        }
    }

    // Analyze binary files
    if (impl_->config.analyze_binary && !binary_paths.empty()) {
        impl_->report_progress(50, 100, "Analyzing binary files");

        // TODO: Implement binary analysis
        // For now, this is a placeholder

        impl_->report_progress(90, 100, "Binary analysis complete");
    }

    // AI analysis (if enabled)
    if (impl_->config.enable_ai && !all_findings.empty()) {
        impl_->report_progress(95, 100, "Running AI analysis");

        // TODO: Implement AI analysis
        // This would:
        // - Run local ML models for classification
        // - Optionally call LLM API for deep analysis
        // - Update confidence scores
        // - Add AI explanations
    }

    impl_->report_progress(100, 100, "Analysis complete");

    return all_findings;
}

void AnalysisOrchestrator::register_detector(std::unique_ptr<detectors::IDetector> detector) {
    if (!detector) {
        return;
    }

    auto metadata = detector->get_metadata();
    if (impl_->config.verbose) {
        std::cout << "Registered detector: " << metadata.name
                  << " v" << metadata.version << std::endl;
    }

    impl_->detectors.push_back(std::move(detector));
}

int AnalysisOrchestrator::load_plugins(const std::string& plugin_dir) {
    if (!impl_->config.enable_plugins) {
        return 0;
    }

    // TODO: Implement plugin loading
    // This would:
    // - Scan plugin_dir for .so/.dll files
    // - Use dlopen/LoadLibrary to load them
    // - Call sentinelx_plugin_create() to instantiate
    // - Register the detector

    if (impl_->config.verbose) {
        std::cout << "Plugin loading not yet implemented" << std::endl;
    }

    return 0;
}

int AnalysisOrchestrator::load_dsl_rules(const std::string& rules_dir) {
    if (!impl_->config.enable_dsl_rules) {
        return 0;
    }

    // TODO: Implement DSL rule loading
    // This would:
    // - Scan rules_dir for .sxr files
    // - Parse and compile each rule
    // - Wrap as IDetector
    // - Register the detector

    if (impl_->config.verbose) {
        std::cout << "DSL rule loading not yet implemented" << std::endl;
    }

    return 0;
}

std::vector<detectors::DetectorMetadata> AnalysisOrchestrator::get_registered_detectors() const {
    std::vector<detectors::DetectorMetadata> metadata_list;

    for (const auto& detector : impl_->detectors) {
        metadata_list.push_back(detector->get_metadata());
    }

    return metadata_list;
}

void AnalysisOrchestrator::set_progress_callback(
    std::function<void(int, int, const std::string&)> callback) {
    impl_->progress_callback = std::move(callback);
}

const AnalyzerConfig& AnalysisOrchestrator::get_config() const {
    return impl_->config;
}

void AnalysisOrchestrator::set_config(const AnalyzerConfig& config) {
    impl_->config = config;

    // Reinitialize CWE repository if path changed
    if (config.cwe_database_path != impl_->config.cwe_database_path) {
        try {
            impl_->cwe_repo = std::make_shared<CweRepository>(config.cwe_database_path);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to reload CWE database: " << e.what() << std::endl;
            impl_->cwe_repo = nullptr;
        }
    }
}

} // namespace sentinelx
