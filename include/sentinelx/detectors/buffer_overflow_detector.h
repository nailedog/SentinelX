#pragma once

#include "detector_interface.h"
#include <vector>
#include <string>
#include <regex>

namespace sentinelx {
namespace detectors {

/**
 * @brief Buffer Overflow Detector
 *
 * Detects buffer overflow vulnerabilities in C/C++ code by identifying:
 * - Dangerous functions (gets, strcpy, strcat, sprintf)
 * - Unsafe scanf usage
 * - Potentially dangerous memcpy/memset operations
 *
 * This is a refactored version extracted from the monolithic detectors.cpp.
 * It demonstrates the new IDetector interface and CWE integration.
 */
class BufferOverflowDetector : public IDetector {
public:
    BufferOverflowDetector() = default;
    ~BufferOverflowDetector() override = default;

    // IDetector interface
    Findings analyze(const AnalysisContext& context) override;
    DetectorMetadata get_metadata() const override;
    std::vector<std::string> get_supported_cwes() const override;

private:
    // Helper methods
    Finding create_unsafe_call_finding(
        const std::string& function_name,
        const std::string& file_path,
        size_t line_number,
        const std::string& code_context,
        Severity severity,
        Confidence confidence
    ) const;

    Finding create_scanf_finding(
        const std::string& file_path,
        size_t line_number,
        const std::string& code_context
    ) const;

    bool is_dangerous_function(const std::string& func) const;
    bool is_scanf_like(const std::string& func) const;

    // Lists of dangerous functions
    static const std::vector<std::string> dangerous_calls_;
    static const std::vector<std::string> scanf_functions_;
};

} // namespace detectors
} // namespace sentinelx
