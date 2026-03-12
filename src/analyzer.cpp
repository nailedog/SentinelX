#include "analyzer.h"

#include "detectors.h"
#include "call_graph.h"
#include "utils.h"

#include <filesystem>

namespace fs = std::filesystem;

namespace sentinel {

Analyzer::Analyzer(AnalyzerConfig config)
    : config_(config) {}

Findings Analyzer::analyze(const std::vector<std::string>& source_paths,
                           const std::vector<std::string>& binary_paths) const {
    Findings all;

    SourceDetector source_detector(config_);
    BinaryDetector binary_detector;

    if (config_.analyze_source) {
        CallGraphAnalyzer call_graph;
        
        if (config_.only_reachable_functions) {
            
            for (const auto& path_str : source_paths) {
                fs::path root(path_str);

                if (!fs::exists(root)) {
                    continue;
                }

                if (fs::is_regular_file(root)) {
                    call_graph.analyze_file(root.string());
                } else if (fs::is_directory(root)) {
                    for (const auto& entry : fs::recursive_directory_iterator(root)) {
                        if (entry.is_regular_file()) {
                            const std::string ext = to_lower(entry.path().extension().string());
                            if (ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx") {
                                call_graph.analyze_file(entry.path().string());
                            }
                        }
                    }
                }
            }
        }

        for (const auto& p : source_paths) {
            Findings f;
            if (config_.only_reachable_functions) {
                f = source_detector.analyze_path_with_call_graph(p, call_graph);
            } else {
                f = source_detector.analyze_path(p);
            }
            all.insert(all.end(), f.begin(), f.end());
        }
    }

    if (config_.analyze_binary) {
        for (const auto& p : binary_paths) {
            Findings f = binary_detector.analyze_binary(p);
            all.insert(all.end(), f.begin(), f.end());
        }
    }

    return all;
}

} 
