#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

#include "binary_parser.h"

#ifdef SENTINELX_USE_LIEF
namespace LIEF {
    class Binary;
}
#endif

namespace sentinel {

struct Instruction {
    std::uint64_t address = 0;
    std::string   text;
    std::string   mnemonic;    // "call", "sub", "add", etc.
    std::string   operands;    // "strcpy@plt", "rsp, 0x100", etc.
    std::vector<std::uint8_t> bytes;  // Raw instruction bytes
    std::size_t   size = 0;    // Instruction size in bytes
    std::int64_t  stack_delta = 0;
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    void load_binary(const std::string& path);

    std::vector<Instruction> disassemble_section(const std::string& section_name);

    std::vector<Instruction> get_context(std::uint64_t address,
                                         const std::vector<Instruction>& all_insts,
                                         std::size_t before = 4,
                                         std::size_t after = 10) const;

    std::vector<Instruction> disassemble_function(const BinaryInfo& binary,
                                                  const std::string& func_name) const;

    std::string find_function_name(const BinaryInfo& binary, std::uint64_t address) const;

    std::uint64_t calculate_return_address(std::uint64_t call_address,
                                           const std::vector<Instruction>& context) const;

    // Check if instruction is potentially dangerous
    bool is_dangerous_instruction(const Instruction& inst) const;

    // Format disassembly with dangerous instructions highlighted
    std::string format_disassembly(const std::vector<Instruction>& instructions,
                                   bool highlight_dangerous = true,
                                   bool show_bytes = false) const;

private:
    void parse_instruction(Instruction& inst) const;
    std::vector<Instruction> disassemble_with_system_tools(const std::string& path,
                                                           const std::string& section_name);

#ifdef SENTINELX_USE_LIEF
    std::unique_ptr<LIEF::Binary> cached_binary_;
#endif
    std::string cached_path_;
    std::unordered_map<std::string, std::vector<Instruction>> section_cache_;
};

}
