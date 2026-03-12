#pragma once

#include <string>
#include <vector>

#include "types.h"

namespace sentinel {

class Analyzer {
public:
    explicit Analyzer(AnalyzerConfig config = {});

    Findings analyze(const std::vector<std::string>& source_paths,
                     const std::vector<std::string>& binary_paths) const;

private:
    AnalyzerConfig config_;
};

} 
