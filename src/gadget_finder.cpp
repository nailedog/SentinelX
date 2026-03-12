#include "gadget_finder.h"
#include <regex>
#include <algorithm>
#include <sstream>

namespace sentinel {
namespace exploit {

GadgetFinder::GadgetFinder(const std::string& binary_path, Architecture arch)
    : binary_path_(binary_path), arch_(arch) {
    disasm_ = std::make_unique<sentinel::Disassembler>();
    disasm_->load_binary(binary_path);
}

std::vector<Gadget> GadgetFinder::find_gadgets(int max_gadget_len) {
    std::vector<Gadget> gadgets;

    auto instructions = disasm_->disassemble_section(".text");
    if (instructions.empty()) {
        return gadgets;
    }

    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto& inst = instructions[i];

        if (inst.mnemonic == "ret" || inst.mnemonic == "retq" ||
            inst.mnemonic == "retn" || inst.mnemonic == "retf") {

            std::vector<Instruction> gadget_insts;
            int start_idx = static_cast<int>(i) - max_gadget_len + 1;
            if (start_idx < 0) start_idx = 0;

            bool valid = true;
            for (int j = start_idx; j <= static_cast<int>(i); ++j) {
                const auto& g_inst = instructions[j];

                if (has_side_effects(g_inst.mnemonic)) {
                    gadget_insts.clear();
                    continue;
                }

                gadget_insts.push_back(g_inst);
            }

            if (!gadget_insts.empty() && gadget_insts.back().mnemonic.find("ret") == 0) {
                Gadget g;
                g.address = gadget_insts.front().address;
                g.pop_count = count_pops_from_instructions(gadget_insts);
                g.has_side_effects = false;

                std::ostringstream oss;
                for (size_t k = 0; k < gadget_insts.size(); ++k) {
                    if (k > 0) oss << " ; ";
                    oss << gadget_insts[k].mnemonic;
                    if (!gadget_insts[k].operands.empty()) {
                        oss << " " << gadget_insts[k].operands;
                    }
                }
                g.disassembly = oss.str();

                gadgets.push_back(g);
            }
        }
    }

    return gadgets;
}

std::vector<Gadget> GadgetFinder::find_by_pattern(const std::string& pattern) {
    auto all_gadgets = find_gadgets();
    std::vector<Gadget> matches;

    std::regex re(pattern, std::regex::icase);

    for (const auto& gadget : all_gadgets) {
        if (std::regex_search(gadget.disassembly, re)) {
            matches.push_back(gadget);
        }
    }

    return matches;
}

std::unordered_map<std::string, Gadget> GadgetFinder::find_pop_ret_gadgets() {
    std::unordered_map<std::string, Gadget> pop_gadgets;

    auto all_gadgets = find_gadgets(3);  

    for (const auto& gadget : all_gadgets) {
        std::regex pop_ret_re(R"(pop\s+(\w+)\s*;\s*ret)");
        std::smatch m;

        if (std::regex_search(gadget.disassembly, m, pop_ret_re)) {
            std::string reg = m[1].str();
            if (pop_gadgets.find(reg) == pop_gadgets.end()) {
                pop_gadgets[reg] = gadget;
            }
        }
    }

    return pop_gadgets;
}

GadgetFinder::UsefulGadgets GadgetFinder::find_useful_gadgets() {
    UsefulGadgets useful;

    auto all_gadgets = find_gadgets();

    for (const auto& gadget : all_gadgets) {
        std::string disasm = gadget.disassembly;

        // Pop ret gadgets
        std::regex pop_ret_re(R"(pop\s+(\w+)\s*;\s*ret)");
        std::smatch m;
        if (std::regex_search(disasm, m, pop_ret_re)) {
            std::string reg = m[1].str();
            if (useful.pop_ret.find(reg) == useful.pop_ret.end()) {
                useful.pop_ret[reg] = gadget;
            }
        }

        // Syscall gadgets
        if (disasm.find("syscall") != std::string::npos &&
            disasm.find("ret") != std::string::npos) {
            useful.syscall_ret.push_back(gadget);
        }

        // int 0x80 gadgets (x86)
        if (disasm.find("int") != std::string::npos &&
            disasm.find("0x80") != std::string::npos &&
            disasm.find("ret") != std::string::npos) {
            useful.int80_ret.push_back(gadget);
        }

        // Mov gadgets
        if (disasm.find("mov") != std::string::npos) {
            useful.mov_gadgets.push_back(gadget);
        }

        if (disasm.find("add") != std::string::npos ||
            disasm.find("sub") != std::string::npos) {
            useful.add_gadgets.push_back(gadget);
        }

        // Exchange gadgets
        if (disasm.find("xchg") != std::string::npos) {
            useful.xchg_gadgets.push_back(gadget);
        }
    }

    return useful;
}

std::optional<Gadget> GadgetFinder::find_set_register(const std::string& reg) {
    auto pop_gadgets = find_pop_ret_gadgets();
    auto it = pop_gadgets.find(reg);
    if (it != pop_gadgets.end()) {
        return it->second;
    }

    std::string pattern = R"(mov\s+)" + reg + R"(\s*,)";
    auto mov_gadgets = find_by_pattern(pattern);
    if (!mov_gadgets.empty()) {
        return mov_gadgets.front();
    }

    return std::nullopt;
}

bool GadgetFinder::has_side_effects(const std::string& mnemonic) {
    static const std::vector<std::string> bad_instructions = {
        "call", "jmp", "je", "jne", "jz", "jnz", "jg", "jl",
        "jge", "jle", "ja", "jb", "jae", "jbe", "jo", "jno",
        "js", "jns", "jp", "jnp", "loop", "int", "syscall",
        "sysenter", "leave"
    };

    for (const auto& bad : bad_instructions) {
        if (mnemonic.find(bad) == 0) {
            if (mnemonic == "syscall" || mnemonic == "int") {
                return false; 
            }
            return true;
        }
    }

    return false;
}

int GadgetFinder::count_pops_from_instructions(const std::vector<sentinel::Instruction>& insts) {
    int count = 0;
    for (const auto& inst : insts) {
        if (inst.mnemonic == "pop" || inst.mnemonic.find("pop") == 0) {
            count++;
        }
    }
    return count;
}

int GadgetFinder::count_pops(const std::string& disassembly) {
    int count = 0;
    std::regex pop_re(R"(\bpop\s+)");

    auto begin = std::sregex_iterator(disassembly.begin(), disassembly.end(), pop_re);
    auto end = std::sregex_iterator();

    return static_cast<int>(std::distance(begin, end));
}

std::string GadgetFinder::extract_pop_register(const std::string& instruction) {
    std::regex pop_re(R"(pop\s+(\w+))");
    std::smatch m;

    if (std::regex_search(instruction, m, pop_re)) {
        return m[1].str();
    }

    return "";
}

std::vector<std::vector<uint8_t>> GadgetFinder::get_ret_opcodes() {
    std::vector<std::vector<uint8_t>> ret_opcodes;

    switch (arch_) {
        case Architecture::X86:
        case Architecture::X86_64:
            ret_opcodes.push_back({0xc3});        // ret
            ret_opcodes.push_back({0xc2});        // ret imm16
            ret_opcodes.push_back({0xcb});        // retf
            ret_opcodes.push_back({0xca});        // retf imm16
            break;

        case Architecture::ARM:
            // ARM: bx lr, pop {pc}, etc.
            ret_opcodes.push_back({0x1e, 0xff, 0x2f, 0xe1});  // bx lr
            break;

        case Architecture::ARM64:
            // ARM64: ret
            ret_opcodes.push_back({0xc0, 0x03, 0x5f, 0xd6});  // ret
            break;

        default:
            break;
    }

    return ret_opcodes;
}

std::optional<Gadget> GadgetFinder::extract_gadget_at(
    const std::vector<uint8_t>& code_section,
    size_t ret_offset,
    uint64_t base_addr,
    int max_len) {
    (void)code_section;
    (void)ret_offset;
    (void)base_addr;
    (void)max_len;
    return std::nullopt;
}

} // namespace exploit
} // namespace sentinel
