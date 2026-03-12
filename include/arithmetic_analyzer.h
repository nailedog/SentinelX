#pragma once

#include <string>

#include "types.h"
#include "binary_parser.h"
#include "disassembler.h"

namespace sentinel {

class ArithmeticAnalyzer {
public:
    explicit ArithmeticAnalyzer(Disassembler& disasm);

    Findings analyze(const BinaryInfo& info);

private:
    Disassembler& disasm_;

    std::string format_context(const std::vector<Instruction>& context,
                               std::uint64_t highlight_addr) const;
    std::string to_hex(std::uint64_t addr) const;
};

} 
