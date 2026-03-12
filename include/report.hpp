#pragma once
#include <string>
#include <vector>
#include <cstddef>

namespace sx {

struct Finding {
    std::string file;
    int         line = 0;
    std::string function;
    std::string buffer;
    std::string kind;      // "buffer_overflow", "tainted_input", etc.
    std::string severity;  // "low" | "medium" | "high" | "INFO" | ...
    std::string confidence; // "LOW" | "MEDIUM" | "HIGH" | "CERTAIN"
    std::string message;
    std::string return_address; 
};

struct AnalysisReport {
    std::vector<Finding> findings;
    std::size_t files_analyzed = 0;

    bool has_issues() const noexcept {
        return !findings.empty();
    }
};

} 
