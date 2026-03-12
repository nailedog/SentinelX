#include "arithmetic_analyzer.h"
#include "utils.h"

#include <sstream>
#include <iomanip>
#include <unordered_map>

namespace sentinel {

ArithmeticAnalyzer::ArithmeticAnalyzer(Disassembler& disasm)
    : disasm_(disasm) {}

Findings ArithmeticAnalyzer::analyze(const BinaryInfo& info) {
    Findings findings;

    auto text_insts = disasm_.disassemble_section(".text");

    if (text_insts.empty()) {
        return findings;
    }

    std::unordered_map<std::uint64_t, std::vector<std::size_t>> clusters;

    for (std::size_t i = 0; i < text_insts.size(); ++i) {
        const auto& inst = text_insts[i];

        if (inst.mnemonic == "add" || inst.mnemonic == "sub" ||
            inst.mnemonic == "mul" || inst.mnemonic == "imul" ||
            inst.mnemonic == "shl" || inst.mnemonic == "sal") {

            std::uint64_t cluster_key = inst.address / 256;  // 256-byte windows
            clusters[cluster_key].push_back(i);
        }
    }

    for (const auto& [key, indices] : clusters) {
        if (indices.size() < 2) {
            continue;
        }

        for (std::size_t idx : indices) {
            const auto& inst = text_insts[idx];

            bool has_overflow_check = false;
            for (std::size_t j = idx + 1; j < idx + 6 && j < text_insts.size(); ++j) {
                const auto& next = text_insts[j];

                if (next.mnemonic == "jo" || next.mnemonic == "jc" ||
                    next.mnemonic == "jno" || next.mnemonic == "jnc" ||
                    next.mnemonic == "jb" || next.mnemonic == "jnb" ||
                    next.mnemonic == "ja" || next.mnemonic == "jbe") {
                    has_overflow_check = true;
                    break;
                }
            }

            if (!has_overflow_check) {
                auto context = disasm_.get_context(inst.address, text_insts, 4, 10);

                Finding f;
                f.kind = FindingKind::Binary;
                f.severity = Severity::Warning;
                f.id = "BIN_INTEGER_OVERFLOW_RISK";
                f.message = "Arithmetic operation '" + inst.mnemonic +
                           "' without overflow check at " + to_hex(inst.address);
                f.recommendation = "Add overflow checks (jo, jc, etc.) after arithmetic operations. "
                                  "Integer overflows can lead to unexpected behavior and vulnerabilities.";
                f.binary_location.arch = info.arch;
                f.binary_location.segment_or_section = ".text";
                f.binary_location.offset = inst.address;
                f.binary_location.disasm = format_context(context, inst.address);

                findings.push_back(f);
                break;  
            }
        }
    }

    for (std::size_t i = 0; i < text_insts.size(); ++i) {
        const auto& inst = text_insts[i];

        if (inst.mnemonic == "call" &&
            (inst.operands.find("printf") != std::string::npos ||
             inst.operands.find("sprintf") != std::string::npos ||
             inst.operands.find("fprintf") != std::string::npos ||
             inst.operands.find("snprintf") != std::string::npos)) {

            bool format_is_constant = false;

            for (int j = static_cast<int>(i) - 1;
                 j >= 0 && j > static_cast<int>(i) - 10;
                 --j) {
                const auto& prev = text_insts[static_cast<std::size_t>(j)];

                if (prev.mnemonic == "lea" &&
                    (prev.operands.find("rdi") != std::string::npos ||
                     prev.operands.find("rcx") != std::string::npos ||
                     prev.operands.find("edi") != std::string::npos ||
                     prev.operands.find("ecx") != std::string::npos)) {

                    if (prev.operands.find("rip") != std::string::npos) {
                        format_is_constant = true;
                        break;
                    }
                }

                if ((prev.mnemonic == "mov" || prev.mnemonic == "movabs") &&
                    (prev.operands.find("rdi") != std::string::npos ||
                     prev.operands.find("rcx") != std::string::npos)) {
                    
                      if (prev.operands.find("$") != std::string::npos ||
                        prev.operands.find("0x") != std::string::npos) {
                        format_is_constant = true;
                        break;
                    }
                }
            }

            if (!format_is_constant) {
                auto context = disasm_.get_context(inst.address, text_insts, 6, 8);

                Finding f;
                f.kind = FindingKind::Binary;
                f.severity = Severity::High;
                f.id = "BIN_FORMAT_STRING_VULN";
                f.message = "Potential format string vulnerability at " +
                           to_hex(inst.address);
                f.recommendation = "Ensure format string is constant, not user-controlled. "
                                  "Format string attacks can lead to information disclosure and arbitrary code execution.";
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

std::string ArithmeticAnalyzer::format_context(
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

std::string ArithmeticAnalyzer::to_hex(std::uint64_t addr) const {
    std::ostringstream oss;
    oss << "0x" << std::hex << addr;
    return oss.str();
}

} 
