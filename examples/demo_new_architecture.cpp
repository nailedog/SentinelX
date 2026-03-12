/**
 * @file demo_new_architecture.cpp
 * @brief Demonstration of SentinelX V-1.5 New Modular Architecture
 *
 * This example shows how to use:
 * - AnalysisOrchestrator
 * - Custom detectors (BufferOverflowDetector)
 * - CWE database integration
 * - Automatic finding enrichment
 */

#include <iostream>
#include <iomanip>
#include <sentinelx/core/orchestrator.h>
#include <sentinelx/detectors/buffer_overflow_detector.h>
#include <sentinelx/cwe/cwe_repository.h>

using namespace sentinelx;

void print_separator() {
    std::cout << std::string(80, '=') << "\n";
}

void print_finding(const Finding& finding, const CweRepository* cwe_repo) {
    print_separator();

    // Basic info
    std::cout << "ID: " << finding.id << "\n";
    std::cout << "Severity: " << severity_to_string(finding.severity) << "\n";
    std::cout << "Confidence: " << confidence_to_string(finding.confidence) << "\n";
    std::cout << "\n";

    // Message
    std::cout << "Message: " << finding.message << "\n";
    std::cout << "Recommendation: " << finding.recommendation << "\n";
    std::cout << "\n";

    // Location
    if (!finding.source_location.file.empty()) {
        std::cout << "Location: " << finding.source_location.file
                  << ":" << finding.source_location.line << "\n";
    }

    // Code context
    if (!finding.source_location.context.empty()) {
        std::cout << "\nCode:\n";
        std::cout << "---\n";
        std::cout << finding.source_location.context << "\n";
        std::cout << "---\n";
    }

    // CWE information (enriched)
    if (finding.cwe_id.has_value()) {
        std::cout << "\nCWE ID: " << finding.cwe_id.value() << "\n";

        if (finding.cwe_name.has_value()) {
            std::cout << "CWE Name: " << finding.cwe_name.value() << "\n";
        }

        // Get additional CWE info from repository
        if (cwe_repo) {
            auto cwe_info = cwe_repo->get_cwe_info(finding.cwe_id.value());
            if (cwe_info.has_value()) {
                std::cout << "CWE Severity: " << cwe_info->severity << "\n";
                std::cout << "CWE Likelihood: " << cwe_info->likelihood << "\n";

                // Get mitigations
                auto mitigations = cwe_repo->get_mitigations(finding.cwe_id.value());
                if (!mitigations.empty()) {
                    std::cout << "\nMitigations:\n";
                    for (const auto& m : mitigations) {
                        std::cout << "  [" << m.phase << "] " << m.description << "\n";
                        std::cout << "    Effectiveness: " << m.effectiveness << "\n";
                    }
                }
            }
        }
    }

    // Detector metadata
    if (!finding.detector_name.empty()) {
        std::cout << "\nDetected by: " << finding.detector_name
                  << " v" << finding.detector_version << "\n";
    }
}

int main(int argc, char* argv[]) {
    std::cout << "SentinelX V-1.5 - New Architecture Demo\n";
    print_separator();

    // Check arguments
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <source_file>\n";
        std::cerr << "\nExample:\n";
        std::cerr << "  " << argv[0] << " examples/vulnerable_test.c\n";
        return 1;
    }

    std::string source_file = argv[1];

    // =============================================================================
    // Step 1: Configure analysis
    // =============================================================================
    std::cout << "\n[Step 1] Configuring analysis...\n";

    AnalyzerConfig config;
    config.analyze_source = true;
    config.analyze_binary = false;
    config.verbose = true;
    config.min_confidence = Confidence::Low;
    config.enrich_with_cwe = true;

    // CWE database path
    config.cwe_database_path = "data/cwe/cwe_database.db";

    std::cout << "  - CWE enrichment: " << (config.enrich_with_cwe ? "ON" : "OFF") << "\n";
    std::cout << "  - CWE database: " << config.cwe_database_path << "\n";

    // =============================================================================
    // Step 2: Create orchestrator
    // =============================================================================
    std::cout << "\n[Step 2] Creating AnalysisOrchestrator...\n";

    AnalysisOrchestrator orchestrator(config);

    // =============================================================================
    // Step 3: Register detectors
    // =============================================================================
    std::cout << "\n[Step 3] Registering detectors...\n";

    // Register BufferOverflowDetector
    orchestrator.register_detector(
        std::make_unique<detectors::BufferOverflowDetector>()
    );

    // Show registered detectors
    auto registered = orchestrator.get_registered_detectors();
    std::cout << "  Registered " << registered.size() << " detector(s):\n";
    for (const auto& meta : registered) {
        std::cout << "    - " << meta.name << " v" << meta.version << "\n";
        std::cout << "      CWEs: ";
        for (size_t i = 0; i < meta.supported_cwes.size(); ++i) {
            std::cout << meta.supported_cwes[i];
            if (i + 1 < meta.supported_cwes.size()) std::cout << ", ";
        }
        std::cout << "\n";
    }

    // =============================================================================
    // Step 4: Analyze file
    // =============================================================================
    std::cout << "\n[Step 4] Analyzing " << source_file << "...\n";
    print_separator();

    std::vector<std::string> sources = {source_file};
    std::vector<std::string> binaries = {};

    Findings findings = orchestrator.analyze(sources, binaries);

    // =============================================================================
    // Step 5: Display results
    // =============================================================================
    print_separator();
    std::cout << "\n[Step 5] Analysis Results\n";
    print_separator();

    std::cout << "\nFound " << findings.size() << " issue(s):\n\n";

    // Open CWE repository for detailed info
    CweRepository* cwe_repo = nullptr;
    try {
        auto repo = std::make_unique<CweRepository>(config.cwe_database_path);
        cwe_repo = repo.get();

        for (const auto& finding : findings) {
            print_finding(finding, cwe_repo);
        }
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not load CWE database: " << e.what() << "\n";
        for (const auto& finding : findings) {
            print_finding(finding, nullptr);
        }
    }

    // =============================================================================
    // Summary
    // =============================================================================
    print_separator();
    std::cout << "\nSummary:\n";
    std::cout << "  Total findings: " << findings.size() << "\n";

    // Count by severity
    int critical = 0, high = 0, warning = 0, info = 0;
    for (const auto& f : findings) {
        switch (f.severity) {
            case Severity::Critical: critical++; break;
            case Severity::High: high++; break;
            case Severity::Warning: warning++; break;
            case Severity::Info: info++; break;
        }
    }

    std::cout << "    Critical: " << critical << "\n";
    std::cout << "    High: " << high << "\n";
    std::cout << "    Warning: " << warning << "\n";
    std::cout << "    Info: " << info << "\n";

    print_separator();

    return findings.empty() ? 0 : 1;
}
