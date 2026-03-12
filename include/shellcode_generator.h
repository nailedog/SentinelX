#pragma once

#include "exploit_types.h"
#include <memory>

namespace sentinel {
namespace exploit {

/**
 * @brief Generates architecture-specific shellcode
 *
 */
class ShellcodeGenerator {
public:
    ShellcodeGenerator() = default;

    /**
     * @brief Generate shellcode for a specific architecture and type
     * @param arch Target architecture
     * @param type Shellcode type (execve, reverse shell, etc.)
     * @param config Optional configuration (for network shellcodes)
     * @return Generated shellcode
     */
    Shellcode generate(Architecture arch,
                      ShellcodeType type,
                      const ExploitConfig* config = nullptr);

    /**
     * @brief Generate execve("/bin/sh") shellcode
     * @param arch Target architecture
     * @return Shellcode that executes /bin/sh
     */
    Shellcode generate_execve_binsh(Architecture arch);

    /**
     * @brief Generate execve("/bin/bash") shellcode
     * @param arch Target architecture
     * @return Shellcode that executes /bin/bash
     */
    Shellcode generate_execve_binbash(Architecture arch);

    /**
     * @brief Check if shellcode contains null bytes
     * @param shellcode Shellcode bytes to check
     * @return true if null bytes are present
     */
    static bool has_null_bytes(const std::vector<uint8_t>& shellcode);

    /**
     * @brief Get description of shellcode
     * @param type Shellcode type
     * @param arch Architecture
     * @return Human-readable description
     */
    static std::string get_description(ShellcodeType type, Architecture arch);

private:
    // x86 (32-bit) shellcode generators
    std::vector<uint8_t> generate_x86_execve_binsh();
    std::vector<uint8_t> generate_x86_execve_binbash();

    // x86_64 (64-bit) shellcode generators
    std::vector<uint8_t> generate_x86_64_execve_binsh();
    std::vector<uint8_t> generate_x86_64_execve_binbash();

    // ARM (32-bit) shellcode generators
    std::vector<uint8_t> generate_arm_execve_binsh();
    std::vector<uint8_t> generate_arm_execve_binbash();

    // ARM64 (AArch64) shellcode generators
    std::vector<uint8_t> generate_arm64_execve_binsh();
    std::vector<uint8_t> generate_arm64_execve_binbash();
};

} // namespace exploit
} // namespace sentinel
