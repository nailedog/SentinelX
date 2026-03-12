#include "call_site_analyzer.h"
#include "utils.h"

#include <sstream>
#include <iomanip>

namespace sentinel {

CallSiteAnalyzer::CallSiteAnalyzer(Disassembler& disasm)
    : disasm_(disasm) {}

Findings CallSiteAnalyzer::analyze(const BinaryInfo& info,
                                   const std::vector<std::string>& dangerous_funcs) {
    Findings findings;

    auto text_instructions = disasm_.disassemble_section(".text");

    if (text_instructions.empty()) {
        return findings;
    }

    for (const auto& inst : text_instructions) {
        if (inst.mnemonic != "call") {
            continue;
        }

        for (const auto& dangerous : dangerous_funcs) {
            if (inst.operands.find(dangerous) != std::string::npos) {
                auto context = disasm_.get_context(inst.address, text_instructions, 4, 10);

                Finding f;
                f.kind = FindingKind::Binary;
                f.severity = severity_for_function(dangerous);
                f.id = "BIN_CALLSITE_" + to_upper(dangerous);
                f.message = "Call to dangerous function '" + dangerous +
                           "' at " + to_hex(inst.address);
                f.recommendation = "Review call site and ensure bounds checking. "
                                  "Consider using safer alternatives (e.g., strncpy, snprintf).";
                f.binary_location.arch = info.arch;
                f.binary_location.segment_or_section = ".text";
                f.binary_location.offset = inst.address;
                f.binary_location.disasm = format_context(context, inst.address);

                findings.push_back(f);
                break; 
            }
        }
    }

    return findings;
}

Severity CallSiteAnalyzer::severity_for_function(const std::string& func) const {
    if (func == "gets") {
        return Severity::Critical;
    }
    if (func == "strcpy" || func == "sprintf" || func == "vsprintf") {
        return Severity::High;
    }
    return Severity::Warning;
}

std::string CallSiteAnalyzer::format_context(
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

std::string CallSiteAnalyzer::to_hex(std::uint64_t addr) const {
    std::ostringstream oss;
    oss << "0x" << std::hex << addr;
    return oss.str();
}

} 
