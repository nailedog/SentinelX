/*
 * Command Injection - VULNERABLE examples
 *
 * Command injection позволяет атакующему выполнить
 * произвольные команды в системе.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// VULN 1: system() с пользовательским вводом
void vuln_system_user_input(char* filename) {
    char command[256];
    sprintf(command, "cat %s", filename);
    system(command);  // CRITICAL: filename может содержать "; rm -rf /"
}

// VULN 2: system() с argv
void vuln_system_argv(int argc, char** argv) {
    char cmd[512];
    if (argc > 1) {
        sprintf(cmd, "ls -la %s", argv[1]);
        system(cmd);  // CRITICAL: argv[1] контролируется пользователем
    }
}

// VULN 3: popen() с пользовательским вводом
void vuln_popen(char* user_file) {
    char command[256];
    sprintf(command, "grep pattern %s", user_file);
    FILE* pipe = popen(command, "r");  // CRITICAL
    if (pipe) pclose(pipe);
}

// VULN 4: execl() с некорректными данными
void vuln_execl(char* user_arg) {
    // Если user_arg = "-rf /", то может быть опасно
    execl("/bin/rm", "rm", user_arg, NULL);  // HIGH
}

// VULN 5: Использование shell через system
void vuln_shell_expansion(char* pattern) {
    char cmd[256];
    sprintf(cmd, "find . -name '%s'", pattern);
    system(cmd);  // CRITICAL: pattern может содержать `command`
}

// VULN 6: Environment variables в команде
void vuln_env_in_command() {
    char* user_path = getenv("USER_PATH");
    char cmd[512];
    sprintf(cmd, "cd %s && ls", user_path);
    system(cmd);  // CRITICAL: USER_PATH контролируется пользователем
}

int main(int argc, char** argv) {
    printf("Command Injection examples (DANGEROUS!)\n");
    // НЕ запускайте эти функции с ненадежными данными!
    return 0;
}
