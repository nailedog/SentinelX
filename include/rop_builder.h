#pragma once

#include "exploit_types.h"
#include "gadget_finder.h"
#include <memory>

namespace sentinel {
namespace exploit {

/**
 * @brief Constructs ROP chains for exploits
 */
class ROPBuilder {
public:
    /**
     * @brief Construct ROP builder
     * @param finder Gadget finder for locating gadgets
     * @param arch Target architecture
     */
    ROPBuilder(std::shared_ptr<GadgetFinder> finder, Architecture arch);

    /**
     * @brief Build ROP chain for a specific type
     * @param type Type of ROP chain to build
     * @param binary_info Binary information (for addresses)
     * @return Constructed ROP chain
     */
    std::optional<ROPChain> build_chain(ROPChainType type,
                                       const BinaryInfo& binary_info);

    /**
     * @brief Build ret2libc chain using system("/bin/sh")
     * @param system_addr Address of system() function
     * @param binsh_addr Address of "/bin/sh" string
     * @return ROP chain for ret2libc
     */
    std::optional<ROPChain> build_ret2libc_system(uint64_t system_addr,
                                                  uint64_t binsh_addr);

    /**
     * @brief Build ROP chain for execve syscall
     * @param binsh_addr Address of "/bin/sh" string
     * @return ROP chain that calls execve("/bin/sh", NULL, NULL)
     */
    std::optional<ROPChain> build_execve_rop(uint64_t binsh_addr);

    /**
     * @brief Build custom ROP chain from specification
     * @param operations Vector of operations to perform
     * @return Custom ROP chain
     */
    struct ROPOperation {
        enum class Type {
            SET_REGISTER,   // Set register to value
            CALL_FUNCTION,  // Call function
            SYSCALL         // Execute syscall
        };

        Type type;
        std::string register_name;
        uint64_t value;
        std::string comment;
    };

    std::optional<ROPChain> build_custom_chain(
        const std::vector<ROPOperation>& operations);

    /**
     * @brief Check if required gadgets are available
     * @param type ROP chain type
     * @return true if all required gadgets can be found
     */
    bool can_build_chain(ROPChainType type);

private:
    std::shared_ptr<GadgetFinder> gadget_finder_;
    Architecture arch_;
    GadgetFinder::UsefulGadgets useful_gadgets_;

    /**
     * @brief Build x86_64 ret2libc chain
     */
    std::optional<ROPChain> build_x86_64_ret2libc_system(uint64_t system_addr,
                                                         uint64_t binsh_addr);

    /**
     * @brief Build x86 (32-bit) ret2libc chain
     */
    std::optional<ROPChain> build_x86_ret2libc_system(uint64_t system_addr,
                                                      uint64_t binsh_addr);

    /**
     * @brief Build x86_64 execve ROP chain
     */
    std::optional<ROPChain> build_x86_64_execve_rop(uint64_t binsh_addr);

    /**
     * @brief Build x86 (32-bit) execve ROP chain
     */
    std::optional<ROPChain> build_x86_execve_rop(uint64_t binsh_addr);

    /**
     * @brief Find gadget to set a register to a value
     * @param reg Register name
     * @return Optional gadget address
     */
    std::optional<uint64_t> find_set_register_gadget(const std::string& reg);

    /**
     * @brief Find syscall gadget
     * @return Optional gadget address
     */
    std::optional<uint64_t> find_syscall_gadget();

    /**
     * @brief Find int 0x80 gadget (x86)
     * @return Optional gadget address
     */
    std::optional<uint64_t> find_int80_gadget();
};

} // namespace exploit
} // namespace sentinel
