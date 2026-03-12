#pragma once

#include "exploit_types.h"
#include "disassembler.h"
#include <memory>
#include <unordered_map>

namespace sentinel {
namespace exploit {

/**
 * @brief Finds useful ROP gadgets in binary code
 *
 * Searches for instruction sequences ending in 'ret' that can be used
 * to construct ROP chains. Filters out gadgets with unwanted side effects.
 */
class GadgetFinder {
public:
    /**
     * @brief Construct gadget finder
     * @param binary_path Path to binary file
     * @param arch Target architecture
     */
    GadgetFinder(const std::string& binary_path, Architecture arch);

    /**
     * @brief Find all useful gadgets in the binary
     * @param max_gadget_len Maximum instructions per gadget (default: 10)
     * @return Vector of found gadgets
     */
    std::vector<Gadget> find_gadgets(int max_gadget_len = 10);

    /**
     * @brief Find gadgets matching a specific pattern
     * @param pattern Regex pattern to match in disassembly
     * @return Vector of matching gadgets
     */
    std::vector<Gadget> find_by_pattern(const std::string& pattern);

    /**
     * @brief Find "pop reg; ret" gadgets
     * @return Map of register name to gadget
     */
    std::unordered_map<std::string, Gadget> find_pop_ret_gadgets();

    /**
     * @brief Find specific gadget types useful for ROP
     * @return Categorized gadgets
     */
    struct UsefulGadgets {
        std::unordered_map<std::string, Gadget> pop_ret;  // pop rdi; ret, etc.
        std::vector<Gadget> syscall_ret;                   // syscall; ret
        std::vector<Gadget> int80_ret;                     // int 0x80; ret
        std::vector<Gadget> mov_gadgets;                   // mov instructions
        std::vector<Gadget> add_gadgets;                   // add/sub instructions
        std::vector<Gadget> xchg_gadgets;                  // exchange registers
    };

    UsefulGadgets find_useful_gadgets();

    /**
     * @brief Find gadget for setting a specific register
     * @param reg Register name (e.g., "rdi", "rsi", "eax")
     * @return Optional gadget that can set the register
     */
    std::optional<Gadget> find_set_register(const std::string& reg);

private:
    std::string binary_path_;
    Architecture arch_;
    std::unique_ptr<sentinel::Disassembler> disasm_;

    /**
     * @brief Search backwards from ret instruction to find gadget
     * @param code_section Code bytes
     * @param ret_offset Offset of ret instruction
     * @param max_len Maximum gadget length
     * @return Optional gadget if valid sequence found
     */
    std::optional<Gadget> extract_gadget_at(const std::vector<uint8_t>& code_section,
                                            size_t ret_offset,
                                            uint64_t base_addr,
                                            int max_len);

    /**
     * @brief Check if instruction has unwanted side effects
     * @param instruction Disassembled instruction
     * @return true if has side effects (calls, jumps, etc.)
     */
    bool has_side_effects(const std::string& instruction);

    /**
     * @brief Count number of pops in instruction sequence
     * @param disassembly Full disassembly of gadget
     * @return Number of pop instructions
     */
    int count_pops(const std::string& disassembly);

    /**
     * @brief Count number of pops from instruction vector
     * @param insts Vector of instructions
     * @return Number of pop instructions
     */
    int count_pops_from_instructions(const std::vector<sentinel::Instruction>& insts);

    /**
     * @brief Get return instruction bytes for architecture
     * @return Vector of possible ret instruction opcodes
     */
    std::vector<std::vector<uint8_t>> get_ret_opcodes();

    /**
     * @brief Extract register name from pop instruction
     * @param instruction Pop instruction string
     * @return Register name or empty string
     */
    std::string extract_pop_register(const std::string& instruction);
};

}
}
