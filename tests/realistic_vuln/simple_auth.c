/*
 * Simple Authentication Server - VULNERABLE VERSION
 *
 * Реалистичный пример программы с уязвимостью переполнения буфера.
 * Имитирует простой сервер аутентификации, который принимает
 * имя пользователя и проверяет его.
 *
 * УЯЗВИМОСТЬ: strcpy() без проверки длины в process_login()
 *
 * Компиляция:
 *   gcc -fno-stack-protector -D_FORTIFY_SOURCE=0 simple_auth.c -o simple_auth
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_USERNAME 32
#define MAX_USERS 3

// База "пользователей"
const char* valid_users[] = {
    "admin",
    "user",
    "guest"
};

// Функция проверки пользователя
int check_user(const char* username) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (strcmp(username, valid_users[i]) == 0) {
            return 1;  // Пользователь найден
        }
    }
    return 0;  // Пользователь не найден
}

// УЯЗВИМАЯ ФУНКЦИЯ: обработка логина
int process_login(const char* user_input) {
    char username[MAX_USERNAME];  // Буфер на стеке
    int authenticated = 0;

    printf("[*] Processing login for: %s\n", user_input);

    // УЯЗВИМОСТЬ: strcpy не проверяет размер!
    // Если user_input > 32 байта, произойдет переполнение
    strcpy(username, user_input);

    // Проверка пользователя
    authenticated = check_user(username);

    if (authenticated) {
        printf("[+] Authentication successful!\n");
        printf("[+] Welcome, %s!\n", username);
        return 1;
    } else {
        printf("[-] Authentication failed.\n");
        printf("[-] Unknown user: %s\n", username);
        return 0;
    }
}

// Функция для демонстрации получения shell
void secret_function() {
    printf("\n");
    printf("========================================\n");
    printf("  SECRET FUNCTION EXECUTED!\n");
    printf("  This should never be called normally.\n");
    printf("========================================\n");
    printf("\n");

    // В реальной эксплуатации здесь был бы execve("/bin/sh")
    // через shellcode в эксплойте
    system("/bin/sh");
}

int main(int argc, char *argv[]) {
    printf("=======================================\n");
    printf("  Simple Authentication Server v1.0\n");
    printf("=======================================\n");
    printf("\n");

    if (argc < 2) {
        printf("Usage: %s <username>\n", argv[0]);
        printf("\nValid users: admin, user, guest\n");
        printf("Try: %s admin\n", argv[0]);
        return 1;
    }

    // Обработка логина
    if (process_login(argv[1])) {
        printf("\n[*] Access granted. Starting session...\n");
        // Здесь был бы код для работы с сессией
    } else {
        printf("\n[*] Access denied.\n");
    }

    return 0;
}
