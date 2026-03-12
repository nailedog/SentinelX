/*
 * Vulnerable Authentication System - x86_64 Version
 *
 * Простая программа с уязвимостью переполнения буфера для демонстрации
 * полной эксплуатации в среде без защит (Docker Ubuntu).
 *
 * Компиляция БЕЗ защит:
 *   gcc -m32 -fno-stack-protector -z execstack -no-pie -o vuln32 vuln_program.c
 *   gcc -m64 -fno-stack-protector -z execstack -no-pie -o vuln64 vuln_program.c
 *
 * Уязвимости:
 *   1. Buffer overflow в read_username() через gets()
 *   2. Buffer overflow в check_password() через strcpy()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERNAME 64
#define MAX_PASSWORD 32

// Секретная функция которую нельзя вызвать напрямую
void secret_backdoor() {
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║   🔓 SECRET BACKDOOR ACTIVATED! 🔓   ║\n");
    printf("║                                        ║\n");
    printf("║  You've successfully exploited the     ║\n");
    printf("║  buffer overflow vulnerability!        ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf("\n");
    printf("[*] Spawning shell...\n");

    // Запускаем shell
    setuid(0);
    setgid(0);
    system("/bin/sh");

    exit(0);
}

// УЯЗВИМАЯ функция 1: gets() не проверяет длину
int read_username(char *username) {
    printf("Username: ");
    fflush(stdout);

    // УЯЗВИМОСТЬ: gets() читает без ограничения длины!
    gets(username);

    return strlen(username);
}

// УЯЗВИМАЯ функция 2: strcpy() без проверки
int check_password(const char *input) {
    char password[MAX_PASSWORD];

    printf("Password: ");
    fflush(stdout);

    // Читаем пароль безопасно (для демонстрации)
    if (fgets(password, sizeof(password), stdin) == NULL) {
        return 0;
    }

    // УЯЗВИМОСТЬ: strcpy может переполнить буфер
    // если input > MAX_PASSWORD
    char buffer[MAX_PASSWORD];
    strcpy(buffer, input);

    // Простая проверка пароля
    if (strcmp(password, "admin123\n") == 0) {
        return 1;
    }

    return 0;
}

void print_banner() {
    printf("\n");
    printf("═══════════════════════════════════════════\n");
    printf("   Secure Login System v1.0 (NOT!)        \n");
    printf("   [Intentionally Vulnerable for Testing]  \n");
    printf("═══════════════════════════════════════════\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    char username[MAX_USERNAME];
    int authenticated = 0;

    print_banner();

    printf("[*] Initializing authentication system...\n");
    printf("[*] Security level: NONE (all protections disabled)\n");
    printf("\n");

    // Читаем имя пользователя (УЯЗВИМО!)
    read_username(username);

    // Простая проверка
    if (strlen(username) > 0) {
        printf("[*] Processing login for: %s\n", username);

        // Проверяем известных пользователей
        if (strcmp(username, "admin") == 0 ||
            strcmp(username, "user") == 0 ||
            strcmp(username, "guest") == 0) {

            printf("[+] User found in database\n");
            authenticated = 1;

        } else {
            printf("[-] Unknown user\n");
        }
    }

    if (authenticated) {
        printf("\n[+] Login successful!\n");
        printf("[+] Welcome, %s!\n", username);
        printf("\n[*] Starting session...\n");
        sleep(1);
        printf("[*] Access granted to system resources\n");
    } else {
        printf("\n[-] Login failed\n");
        printf("[-] Access denied\n");
    }

    return 0;
}

/*
 * EXPLOIT NOTES:
 *
 * Для эксплуатации через read_username():
 * 1. Найти offset до return address (64 + saved EBP/RBP + ...)
 * 2. Создать payload: NOP sled + shellcode + padding + return address
 * 3. Return address должен указывать на NOP sled или shellcode
 *
 * x86_64 (64-bit):
 *   - Buffer: 64 bytes
 *   - Saved RBP: 8 bytes
 *   - Return address: 8 bytes
 *   - Total offset: ~72-80 bytes
 *
 * x86 (32-bit):
 *   - Buffer: 64 bytes
 *   - Saved EBP: 4 bytes
 *   - Return address: 4 bytes
 *   - Total offset: ~68-76 bytes
 *
 * Shellcode можно разместить:
 *   - В самом буфере (если достаточно места)
 *   - В переменных окружения
 *   - В аргументах командной строки
 */
