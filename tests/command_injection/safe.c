/*
 * Command Injection - SAFE examples
 *
 * Безопасное выполнение команд без риска injection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

// SAFE 1: Использование execv вместо system (нет shell)
void safe_execv(char* filename) {
    char* args[] = {"cat", filename, NULL};
    // execv не использует shell, поэтому нет интерпретации спецсимволов
    pid_t pid = fork();
    if (pid == 0) {
        execv("/bin/cat", args);  // SAFE: нет shell expansion
        exit(1);
    }
}

// SAFE 2: Валидация ввода перед использованием
int is_safe_filename(const char* filename) {
    // Только буквы, цифры, точки, дефисы
    for (const char* p = filename; *p; p++) {
        if (!isalnum(*p) && *p != '.' && *p != '-' && *p != '_') {
            return 0;
        }
    }
    return 1;
}

void safe_validated_system(char* filename) {
    if (!is_safe_filename(filename)) {
        fprintf(stderr, "Invalid filename\n");
        return;
    }
    char command[256];
    snprintf(command, sizeof(command), "cat %s", filename);
    system(command);  // SAFE: filename проверен
}

// SAFE 3: Использование whitelist команд
void safe_whitelist_command(const char* cmd) {
    const char* allowed[] = {"ls", "pwd", "whoami", NULL};

    for (int i = 0; allowed[i]; i++) {
        if (strcmp(cmd, allowed[i]) == 0) {
            system(cmd);  // SAFE: команда из whitelist
            return;
        }
    }
    fprintf(stderr, "Command not allowed\n");
}

// SAFE 4: Экранирование специальных символов
void escape_shell_arg(char* dest, const char* src, size_t dest_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dest_size - 2; i++) {
        if (strchr(";|&$`<>\"'\\", src[i])) {
            dest[j++] = '\\';
        }
        dest[j++] = src[i];
    }
    dest[j] = '\0';
}

void safe_escaped_command(char* user_input) {
    char escaped[512];
    escape_shell_arg(escaped, user_input, sizeof(escaped));
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "echo %s", escaped);
    system(cmd);  // SAFE: символы экранированы
}

// SAFE 5: Использование библиотечных функций вместо shell команд
void safe_use_library(const char* filename) {
    // Вместо "cat file", читаем напрямую
    FILE* f = fopen(filename, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            printf("%s", line);
        }
        fclose(f);
    }  // SAFE: нет команд вообще
}

int main() {
    printf("Safe command execution examples\n");
    safe_validated_system("test.txt");
    safe_whitelist_command("ls");
    safe_use_library("data.txt");
    return 0;
}
