#include "../../include/sentinelx/detectors/buffer_overflow_detector.h"
#include <regex>
#include <sstream>

namespace sentinelx {
namespace detectors {

// Static member initialization
const std::vector<std::string> BufferOverflowDetector::dangerous_calls_ = {
    "strcpy", "wcscpy",
    "strcat", "wcscat",
    "gets",
    "sprintf", "vsprintf"
};

const std::vector<std::string> BufferOverflowDetector::scanf_functions_ = {
    "scanf", "fscanf", "sscanf",
    "wscanf", "fwscanf", "swscanf"
};

// =============================================================================
// IDetector Implementation
// =============================================================================

Findings BufferOverflowDetector::analyze(const AnalysisContext& context) {
    Findings findings;

    // Check if we have source code to analyze
    if (!context.has_source()) {
        return findings;
    }

    const std::string& source_code = context.source_code.value();
    const std::string& file_path = context.file_path.value_or("unknown");

    // Split code into lines for line number tracking
    std::istringstream code_stream(source_code);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(code_stream, line)) {
        lines.push_back(line);
    }

    // Analyze each line
    for (size_t line_no = 0; line_no < lines.size(); ++line_no) {
        const std::string& current_line = lines[line_no];

        // Check for dangerous function calls
        for (const auto& func : dangerous_calls_) {
            std::string pattern = R"(\b)" + func + R"(\s*\()";
            std::regex func_regex(pattern);

            if (std::regex_search(current_line, func_regex)) {
                // Determine severity based on function
                Severity sev = Severity::High;
                Confidence conf = Confidence::High;

                if (func == "gets") {
                    // gets() is always critical
                    sev = Severity::Critical;
                    conf = Confidence::Certain;
                } else if (func == "strcpy" || func == "strcat" || func == "wcscpy" || func == "wcscat") {
                    sev = Severity::High;
                    conf = Confidence::High;
                } else if (func == "sprintf" || func == "vsprintf") {
                    sev = Severity::High;
                    conf = Confidence::Medium;
                }

                // Create context (3 lines: before, current, after)
                std::string code_context;
                if (line_no > 0) {
                    code_context += lines[line_no - 1] + "\n";
                }
                code_context += current_line + "\n";
                if (line_no + 1 < lines.size()) {
                    code_context += lines[line_no + 1];
                }

                Finding finding = create_unsafe_call_finding(
                    func,
                    file_path,
                    line_no + 1,  // 1-based line numbers
                    code_context,
                    sev,
                    conf
                );

                findings.push_back(finding);
            }
        }

        // Check for scanf with unbounded %s
        for (const auto& func : scanf_functions_) {
            std::string pattern = R"(\b)" + func + R"(\s*\([^)]*%s)";
            std::regex scanf_regex(pattern);

            if (std::regex_search(current_line, scanf_regex)) {
                // Check if it's unbounded (no width specifier like %10s)
                std::regex bounded_regex(R"(%\d+s)");
                if (!std::regex_search(current_line, bounded_regex)) {
                    std::string code_context;
                    if (line_no > 0) {
                        code_context += lines[line_no - 1] + "\n";
                    }
                    code_context += current_line + "\n";
                    if (line_no + 1 < lines.size()) {
                        code_context += lines[line_no + 1];
                    }

                    Finding finding = create_scanf_finding(
                        file_path,
                        line_no + 1,
                        code_context
                    );

                    findings.push_back(finding);
                }
            }
        }
    }

    return findings;
}

DetectorMetadata BufferOverflowDetector::get_metadata() const {
    DetectorMetadata meta;
    meta.name = "BufferOverflowDetector";
    meta.version = "1.0.0";
    meta.author = "SentinelX Team";
    meta.description = "Detects buffer overflow vulnerabilities from dangerous function calls";

    meta.supported_languages = {"C", "C++"};
    meta.requires_source = true;
    meta.requires_binary = false;
    meta.requires_call_graph = false;
    meta.requires_taint_analysis = false;

    meta.supported_cwes = {"CWE-120", "CWE-787", "CWE-676"};

    meta.is_expensive = false;
    meta.supports_parallel = true;

    return meta;
}

std::vector<std::string> BufferOverflowDetector::get_supported_cwes() const {
    return {"CWE-120", "CWE-787", "CWE-676"};
}

// =============================================================================
// Helper Methods
// =============================================================================

Finding BufferOverflowDetector::create_unsafe_call_finding(
    const std::string& function_name,
    const std::string& file_path,
    size_t line_number,
    const std::string& code_context,
    Severity severity,
    Confidence confidence) const {

    Finding finding;

    // Core identification
    finding.kind = FindingKind::Source;
    finding.severity = severity;
    finding.confidence = confidence;
    finding.id = "SRC_UNSAFE_CALL_" + function_name;

    // Message and recommendation
    finding.message = "Call to potentially unsafe function '" + function_name +
                     "' without explicit bounds checking.";

    std::string recommendation;
    if (function_name == "gets") {
        recommendation = "Replace gets() with fgets() which allows buffer size specification.";
    } else if (function_name == "strcpy" || function_name == "wcscpy") {
        recommendation = "Use strncpy() or strlcpy() with explicit size limits.";
    } else if (function_name == "strcat" || function_name == "wcscat") {
        recommendation = "Use strncat() or strlcat() with explicit size limits.";
    } else if (function_name == "sprintf" || function_name == "vsprintf") {
        recommendation = "Use snprintf() or vsnprintf() with explicit buffer size.";
    } else {
        recommendation = "Prefer bounded alternatives and ensure buffer size checks.";
    }
    finding.recommendation = recommendation;

    // Source location
    finding.source_location.file = file_path;
    finding.source_location.line = line_number;
    finding.source_location.context = code_context;

    // CWE will be filled by orchestrator via mapping
    // But we can hint it here
    finding.cwe_id = "CWE-120";  // Buffer Copy without Checking Size

    // Detector metadata
    finding.detector_name = "BufferOverflowDetector";
    finding.detector_version = "1.0.0";

    return finding;
}

Finding BufferOverflowDetector::create_scanf_finding(
    const std::string& file_path,
    size_t line_number,
    const std::string& code_context) const {

    Finding finding;

    finding.kind = FindingKind::Source;
    finding.severity = Severity::High;
    finding.confidence = Confidence::High;
    finding.id = "SRC_SCANF_UNBOUNDED";

    finding.message = "scanf family function with unbounded %s format specifier. "
                     "This can lead to buffer overflow.";
    finding.recommendation = "Use bounded format specifiers (e.g., %10s) to limit input size, "
                            "or use fgets() with manual parsing.";

    finding.source_location.file = file_path;
    finding.source_location.line = line_number;
    finding.source_location.context = code_context;

    finding.cwe_id = "CWE-120";

    finding.detector_name = "BufferOverflowDetector";
    finding.detector_version = "1.0.0";

    return finding;
}

bool BufferOverflowDetector::is_dangerous_function(const std::string& func) const {
    return std::find(dangerous_calls_.begin(), dangerous_calls_.end(), func) != dangerous_calls_.end();
}

bool BufferOverflowDetector::is_scanf_like(const std::string& func) const {
    return std::find(scanf_functions_.begin(), scanf_functions_.end(), func) != scanf_functions_.end();
}

} // namespace detectors
} // namespace sentinelx
