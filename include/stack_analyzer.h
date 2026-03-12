#pragma once

#include <string>
#include <cstddef>

#include "types.h"
#include "binary_parser.h"
#include "disassembler.h"

namespace sentinel {

class StackAnalyzer {
public:
    explicit StackAnalyzer(Disassembler& disasm);

    Findings analyze(const BinaryInfo& info);

private:
    Disassembler& disasm_;

    static constexpr std::size_t LARGE_STACK_THRESHOLD = 1024; // bytes

    std::size_t parse_stack_size(const std::string& operands) const;
    std::string format_context(const std::vector<Instruction>& context,
                               std::uint64_t highlight_addr) const;
    std::string to_hex(std::uint64_t addr) const;
};

}
