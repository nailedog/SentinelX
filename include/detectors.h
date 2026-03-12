#pragma once

#include <string>

#include "types.h"
#include "call_graph.h"

namespace sentinel {

class SourceDetector {
public:
    SourceDetector() = default;
    explicit SourceDetector(const AnalyzerConfig& config) : config_(config) {}

    Findings analyze_path(const std::string& path) const;
    Findings analyze_path_with_call_graph(const std::string& path,
                                          CallGraphAnalyzer& call_graph) const;

private:
    AnalyzerConfig config_;
};

class BinaryDetector {
public:
    Findings analyze_binary(const std::string& path) const;
};

} 
