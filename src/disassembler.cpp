#include "disassembler.h"
#include "utils.h"

#ifdef SENTINELX_USE_LIEF
#  include <LIEF/LIEF.hpp>
#endif

#include <sstream>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cstdio>
#include <memory>
#include <array>
#include <regex>

namespace sentinel {

Disassembler::Disassembler() = default;

Disassembler::~Disassembler() = default;

void Disassembler::load_binary(const std::string& path) {
#ifdef SENTINELX_USE_LIEF
    if (cached_path_ == path && cached_binary_) {
        return; 
    }

    cached_binary_ = LIEF::Parser::parse(path);
    if (cached_binary_) {
        cached_path_ = path;
        section_cache_.clear();
    }
#else
    (void)path;
#endif
}

std::vector<Instruction> Disassembler::disassemble_section(const std::string& section_name) {
    auto it = section_cache_.find(section_name);
    if (it != section_cache_.end()) {
        return it->second;
    }

    std::vector<Instruction> result;

#ifdef SENTINELX_USE_LIEF
    if (!cached_binary_) {
        return result;
    }

    LIEF::Section* section = nullptr;
    for (auto& sec : cached_binary_->sections()) {
        std::string sec_name = sec.name();
        if (sec_name.find(section_name) != std::string::npos) {
            section = &sec;
            break;
        }
    }

    if (!section) {
        return result;
    }

    uint64_t start_addr = section->virtual_address();
    uint64_t size = section->size();

    auto lief_insts = cached_binary_->disassemble(start_addr, size);

    for (auto inst_ptr : lief_insts) {
        if (!inst_ptr) continue;

        Instruction inst;
        inst.address = inst_ptr->address();
        inst.text = inst_ptr->to_string(true);

        parse_instruction(inst);

        result.push_back(std::move(inst));
    }

    // If LIEF disassembly failed, try system tools
    if (result.empty() && !cached_path_.empty()) {
        result = disassemble_with_system_tools(cached_path_, section_name);
    }

    section_cache_[section_name] = result;
#else
    (void)section_name;
#endif

    return result;
}

std::vector<Instruction> Disassembler::get_context(std::uint64_t address,
                                                   const std::vector<Instruction>& all_insts,
                                                   std::size_t before,
                                                   std::size_t after) const {
    std::vector<Instruction> context;

    auto it = std::find_if(all_insts.begin(), all_insts.end(),
                          [address](const Instruction& i) {
                              return i.address == address;
                          });

    if (it == all_insts.end()) {
        return context;
    }

    std::size_t idx = static_cast<std::size_t>(std::distance(all_insts.begin(), it));

    std::size_t start_idx = (idx >= before) ? (idx - before) : 0;
    std::size_t end_idx = std::min(idx + after + 1, all_insts.size());

    for (std::size_t i = start_idx; i < end_idx; ++i) {
        context.push_back(all_insts[i]);
    }

    return context;
}

void Disassembler::parse_instruction(Instruction& inst) const {
    // "call   0x401020 <strcpy@plt>" -> mnemonic="call", operands="0x401020 <strcpy@plt>"

    std::string trimmed = trim(inst.text);

    std::size_t space_pos = trimmed.find_first_of(" \t");
    if (space_pos == std::string::npos) {
        inst.mnemonic = trimmed;
        inst.operands = "";
    } else {
        inst.mnemonic = trimmed.substr(0, space_pos);
        inst.operands = trim(trimmed.substr(space_pos + 1));
    }

    if (inst.mnemonic == "sub") {
        if (inst.operands.find("sp") != std::string::npos ||
            inst.operands.find("rsp") != std::string::npos) {

            std::size_t hash_pos = inst.operands.find("#0x");
            std::size_t comma_pos = inst.operands.find("0x");

            if (hash_pos != std::string::npos) {
                std::string val_str = inst.operands.substr(hash_pos + 1);
                try {
                    inst.stack_delta = -static_cast<std::int64_t>(std::stoull(val_str, nullptr, 16));
                } catch (...) {}
            } else if (comma_pos != std::string::npos) {
                std::string val_str = inst.operands.substr(comma_pos);
                try {
                    inst.stack_delta = -static_cast<std::int64_t>(std::stoull(val_str, nullptr, 16));
                } catch (...) {}
            }
        }
    } else if (inst.mnemonic == "add") {
        bool modifies_sp = false;
        if (inst.operands.find("sp, sp") != std::string::npos ||
            inst.operands.find("rsp") == 0) {  // rsp at start means it's the destination
            modifies_sp = true;
        }

        if (modifies_sp) {
            std::size_t hash_pos = inst.operands.find("#0x");
            std::size_t comma_pos = inst.operands.find("0x");

            if (hash_pos != std::string::npos) {
                std::string val_str = inst.operands.substr(hash_pos + 1);
                try {
                    inst.stack_delta = static_cast<std::int64_t>(std::stoull(val_str, nullptr, 16));
                } catch (...) {}
            } else if (comma_pos != std::string::npos) {
                std::string val_str = inst.operands.substr(comma_pos);
                try {
                    inst.stack_delta = static_cast<std::int64_t>(std::stoull(val_str, nullptr, 16));
                } catch (...) {}
            }
        }
    } else if (inst.mnemonic == "stp" || inst.mnemonic == "push") {
        // Only track if it's a pre-decrement store (modifies sp)
        // ARM64: stp x29, x30, [sp, #-0x10]! -> pre-decrement (modifies sp)
        // ARM64: stp x29, x30, [sp, #0x10] -> no sp modification
        // x86_64: push rbp -> modifies sp
        if (inst.mnemonic == "push") {
            inst.stack_delta = -8;   // Saves one 64-bit register (x86_64)
        } else if (inst.operands.find("[sp, #-") != std::string::npos &&
                   inst.operands.find("]!") != std::string::npos) {
            inst.stack_delta = -16;  // Pre-decrement stp (ARM64)
        }
        // Otherwise, no stack pointer modification
    } else if (inst.mnemonic == "ldp" || inst.mnemonic == "pop") {
        // Only track if it's a post-increment load (modifies sp)
        // ARM64: ldp x29, x30, [sp], #0x10 -> post-increment (modifies sp)
        // x86_64: pop rbp -> modifies sp
        if (inst.mnemonic == "pop") {
            inst.stack_delta = 8;    // Restores one 64-bit register (x86_64)
        } else if (inst.operands.find("[sp], #") != std::string::npos) {
            inst.stack_delta = 16;   // Post-increment ldp (ARM64)
        }
        // Otherwise, no stack pointer modification
    }
}

std::vector<Instruction> Disassembler::disassemble_with_system_tools(
    const std::string& path, const std::string& section_name) {

    std::vector<Instruction> result;

    std::string cmd;

#ifdef __APPLE__
    cmd = "otool -tV \"" + path + "\" 2>/dev/null";
#else
    cmd = "objdump -d --section=" + section_name + " \"" + path + "\" 2>/dev/null";
#endif

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return result;
    }

    std::array<char, 256> buffer;
    std::string output;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        output += buffer.data();
    }
    pclose(pipe);

    // Parse output line by line
    // otool format: "0000000100000498\tsub\tsp, sp, #0x40"
    // objdump format: "  401020:  ff 15 02 20 00 00   callq  0x603028"

    std::istringstream iss(output);
    std::string line;

    std::regex addr_inst_re(R"(^([0-9a-fA-F]+)[\s:]+(.+))");

    int count = 0;
    while (std::getline(iss, line)) {
        std::smatch match;
        if (std::regex_search(line, match, addr_inst_re)) {
            try {
                std::string addr_str = match[1].str();
                std::string inst_str = match[2].str();

                if (inst_str.empty() || inst_str.find("section") != std::string::npos) {
                    continue;
                }

                Instruction inst;
                inst.address = std::stoull(addr_str, nullptr, 16);
                inst.text = trim(inst_str);
                parse_instruction(inst);
                result.push_back(inst);
                count++;
            } catch (...) {
                // Skip malformed
            }
        }
    }

    return result;
}

std::vector<Instruction> Disassembler::disassemble_function(const BinaryInfo& info,
                                                            const std::string& func_name) const {
    std::vector<Instruction> result;

#ifdef SENTINELX_USE_LIEF
    // Find function in BinaryInfo
    std::uint64_t func_addr = 0;
    std::uint64_t func_size = 0;

    for (const auto& func : info.functions) {
        if (func.name == func_name) {
            func_addr = func.address;
            func_size = func.size;
            break;
        }
    }

    if (func_addr == 0) {
        return result; // Function not found
    }

    // For macOS, use system tools (otool) since LIEF may not work well
    #ifdef __APPLE__
    std::string cmd = "otool -tV \"" + info.path + "\" 2>/dev/null | "
                      "awk '/" + func_name + ":/{flag=1;next}/:$/{flag=0}flag'";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        std::array<char, 256> buffer;
        std::string output;
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            output += buffer.data();
        }
        pclose(pipe);

        // Parse output line by line
        std::istringstream iss(output);
        std::string line;
        std::regex addr_inst_re(R"(^([0-9a-fA-F]+)[\s]+(.+))");

        while (std::getline(iss, line)) {
            std::smatch match;
            if (std::regex_search(line, match, addr_inst_re)) {
                try {
                    std::string addr_str = match[1].str();
                    std::string inst_str = match[2].str();

                    if (inst_str.empty()) {
                        continue;
                    }

                    Instruction inst;
                    inst.address = std::stoull(addr_str, nullptr, 16);
                    inst.text = trim(inst_str);
                    parse_instruction(inst);
                    result.push_back(inst);

                    // Stop at return instruction (simple heuristic)
                    if (inst.mnemonic == "ret" || inst.mnemonic == "retq" ||
                        inst.mnemonic == "retn") {
                        break;
                    }
                } catch (...) {
                    continue;
                }
            }
        }
    }

    if (!result.empty()) {
        return result;
    }
    #endif

    // Fallback to LIEF
    std::unique_ptr<LIEF::Binary> binary = LIEF::Parser::parse(info.path);
    if (!binary) {
        return result;
    }

    // Try to disassemble by name first
    auto insts = binary->disassemble(func_name);

    // If that fails, try by address
    if (insts.empty() && func_size > 0) {
        insts = binary->disassemble(func_addr, func_size);
    }

    // If size is not available, try a reasonable default
    if (insts.empty()) {
        insts = binary->disassemble(func_addr, 512); // Default 512 bytes
    }

    for (auto inst : insts) {
        if (!inst) continue;
        Instruction i;
        i.address = inst->address();
        i.text = inst->to_string(true);

        parse_instruction(i);
        result.push_back(std::move(i));
    }
#else
    (void)info;
    (void)func_name;
#endif

    return result;
}

std::string Disassembler::find_function_name(const BinaryInfo& binary, std::uint64_t address) const {
    for (const auto& func : binary.functions) {
        if (func.size > 0) {
            if (address >= func.address && address < func.address + func.size) {
                return func.name;
            }
        }
    }

    std::string best_match = "<unknown>";
    std::uint64_t best_distance = UINT64_MAX;

    for (const auto& func : binary.functions) {
        if (func.address <= address) {
            std::uint64_t distance = address - func.address;
            if (distance < 4096 && distance < best_distance) {
                best_distance = distance;
                best_match = func.name;
            }
        }
    }

    return best_match;
}

std::uint64_t Disassembler::calculate_return_address(std::uint64_t call_address,
                                                     const std::vector<Instruction>& context) const {
    auto call_it = std::find_if(context.begin(), context.end(),
                                [call_address](const Instruction& i) {
                                    return i.address == call_address;
                                });

    if (call_it == context.end()) {
        return 0;
    }

    auto next_it = call_it + 1;
    if (next_it != context.end()) {
        return next_it->address;
    }

    return call_address + 5;
}

bool Disassembler::is_dangerous_instruction(const Instruction& inst) const {
    // List of dangerous function calls
    static const std::vector<std::string> dangerous_functions = {
        "strcpy", "wcscpy", "strcat", "wcscat", "gets", "sprintf", "vsprintf",
        "scanf", "fscanf", "sscanf", "printf", "fprintf",
        "memcpy", "memmove", "strncpy", "strncat",
        "system", "popen", "exec"
    };

    // Check for dangerous function calls
    if (inst.mnemonic == "call" || inst.mnemonic == "bl" || inst.mnemonic == "blr") {
        for (const auto& func : dangerous_functions) {
            if (inst.operands.find(func) != std::string::npos) {
                return true;
            }
        }
    }

    // Stack manipulation that could be exploited
    if (inst.mnemonic == "ret" || inst.mnemonic == "retn") {
        return true; // Return instructions are critical for ROP
    }

    // System calls
    if (inst.mnemonic == "syscall" || inst.mnemonic == "sysenter" ||
        inst.mnemonic == "int" || inst.mnemonic == "svc") {
        return true;
    }

    // Indirect jumps/calls (could be hijacked)
    if ((inst.mnemonic == "jmp" || inst.mnemonic == "call") &&
        (inst.operands.find("[") != std::string::npos ||
         inst.operands.find("r") == 0 || inst.operands.find("e") == 0)) {
        return true;
    }

    return false;
}

std::string Disassembler::format_disassembly(const std::vector<Instruction>& instructions,
                                             bool highlight_dangerous,
                                             bool show_bytes) const {
    std::ostringstream oss;

    // ANSI color codes
    const std::string RED = "\033[1;31m";
    const std::string YELLOW = "\033[1;33m";
    const std::string RESET = "\033[0m";
    const std::string BOLD = "\033[1m";

    for (const auto& inst : instructions) {
        bool is_dangerous = highlight_dangerous && is_dangerous_instruction(inst);

        // Format: address: [bytes] mnemonic operands
        if (is_dangerous) {
            oss << RED << "=> ";
        } else {
            oss << "   ";
        }

        // Address
        oss << "0x" << std::hex << std::setw(8) << std::setfill('0')
            << inst.address << std::dec << ": ";

        // Bytes (optional)
        if (show_bytes && !inst.bytes.empty()) {
            for (size_t i = 0; i < std::min(inst.bytes.size(), size_t(6)); ++i) {
                oss << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(inst.bytes[i]) << " ";
            }
            oss << std::dec << std::setw(20 - static_cast<int>(inst.bytes.size() * 3)) << " ";
        }

        // Instruction text
        if (is_dangerous) {
            oss << BOLD << std::left << std::setw(8) << std::setfill(' ')
                << inst.mnemonic << " " << inst.operands << RESET;

            // Add danger indicator
            oss << "  " << YELLOW << "[!]" << RESET;
        } else {
            oss << std::left << std::setw(8) << std::setfill(' ')
                << inst.mnemonic << " " << inst.operands;
        }

        oss << "\n";
    }

    return oss.str();
}

}
