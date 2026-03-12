#pragma once

#include <string>
#include <vector>

#include "types.h"
#include "binary_parser.h"
#include "disassembler.h"

namespace sentinel {

class CallSiteAnalyzer {
public:
    explicit CallSiteAnalyzer(Disassembler& disasm);

    Findings analyze(const BinaryInfo& info,
                    const std::vector<std::string>& dangerous_funcs);

private:
    Disassembler& disasm_;

    Severity severity_for_function(const std::string& func) const;
    std::string format_context(const std::vector<Instruction>& context,
                               std::uint64_t highlight_addr) const;
    std::string to_hex(std::uint64_t addr) const;
};

} 
