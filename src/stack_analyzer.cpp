#include "stack_analyzer.h"
#include "utils.h"

#include <sstream>
#include <iomanip>

namespace sentinel {

StackAnalyzer::StackAnalyzer(Disassembler& disasm)
    : disasm_(disasm) {}

Findings StackAnalyzer::analyze(const BinaryInfo& info) {
    Findings findings;

    auto text_insts = disasm_.disassemble_section(".text");

    if (text_insts.empty()) {
        return findings;
    }

    for (std::size_t i = 0; i < text_insts.size(); ++i) {
        const auto& inst = text_insts[i];

        if (inst.mnemonic == "sub" &&
            (inst.operands.find("rsp") != std::string::npos ||
             inst.operands.find("esp") != std::string::npos)) {

            std::size_t stack_size = parse_stack_size(inst.operands);

            if (stack_size >= LARGE_STACK_THRESHOLD) {
                auto context = disasm_.get_context(inst.address, text_insts, 2, 12);

                Finding f;
                f.kind = FindingKind::Binary;
                f.severity = Severity::Warning;
                f.id = "BIN_LARGE_STACK_FRAME";
                f.message = "Large stack allocation of " +
                           std::to_string(stack_size) +
                           " bytes at " + to_hex(inst.address);
                f.recommendation = "Large stack buffers may cause stack overflow. "
                                  "Consider heap allocation or reduce size.";
                f.binary_location.arch = info.arch;
                f.binary_location.segment_or_section = ".text";
                f.binary_location.offset = inst.address;
                f.binary_location.disasm = format_context(context, inst.address);

                findings.push_back(f);
            }
        }

        if (inst.mnemonic.find("rep") == 0) {
            if (inst.mnemonic.find("movs") != std::string::npos ||
                inst.mnemonic.find("stos") != std::string::npos) {

                auto context = disasm_.get_context(inst.address, text_insts, 4, 10);

                Finding f;
                f.kind = FindingKind::Binary;
                f.severity = Severity::High;
                f.id = "BIN_DANGEROUS_STRING_OP";
                f.message = "Potentially unbounded string operation '" +
                           inst.mnemonic + "' at " + to_hex(inst.address);
                f.recommendation = "Ensure ECX/RCX register contains bounded count. "
                                  "Unbounded rep operations can lead to buffer overflows.";
                f.binary_location.arch = info.arch;
                f.binary_location.segment_or_section = ".text";
                f.binary_location.offset = inst.address;
                f.binary_location.disasm = format_context(context, inst.address);

                findings.push_back(f);
            }
        }
    }

    return findings;
}

std::size_t StackAnalyzer::parse_stack_size(const std::string& operands) const {
    std::size_t pos = operands.find("0x");
    if (pos != std::string::npos) {
        try {
            return std::stoull(operands.substr(pos), nullptr, 16);
        } catch (...) {
            return 0;
        }
    }

    pos = operands.find_last_of(" ,");
    if (pos == std::string::npos) {
        return 0;
    }

    try {
        return std::stoull(operands.substr(pos + 1));
    } catch (...) {
        return 0;
    }
}

std::string StackAnalyzer::format_context(
    const std::vector<Instruction>& context,
    std::uint64_t highlight_addr) const {

    std::ostringstream oss;
    for (const auto& inst : context) {
        if (inst.address == highlight_addr) {
            oss << ">>> ";
        } else {
            oss << "    ";
        }
        oss << to_hex(inst.address) << ": " << inst.text << "\n";
    }
    return oss.str();
}

std::string StackAnalyzer::to_hex(std::uint64_t addr) const {
    std::ostringstream oss;
    oss << "0x" << std::hex << addr;
    return oss.str();
}

} 
