/*
 * Format String Vulnerability - VULNERABLE examples
 *
 * Format string уязвимости позволяют атакующему:
 * - Читать память (information disclosure)
 * - Записывать в произвольные адреса памяти (code execution)
 * - Вызвать crash программы
 *
 * Должны быть обнаружены с CRITICAL severity
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

// VULN 1: printf() с пользовательским вводом
void vuln_printf_user_input(char* user_input) {
    printf(user_input);  // CRITICAL: format string контролируется пользователем
    // Атака: "./program '%x %x %x %x %s %s %s'"
}

// VULN 2: printf() с argv
void vuln_printf_argv(int argc, char** argv) {
    if (argc > 1) {
        printf(argv[1]);  // CRITICAL CERTAIN: argv - точно user input
    }
}

// VULN 3: fprintf() с пользовательским вводом
void vuln_fprintf(char* message) {
    fprintf(stderr, message);  // CRITICAL: format string от пользователя
}

// VULN 4: sprintf() с format от пользователя
void vuln_sprintf(char* format_str) {
    char buffer[256];
    sprintf(buffer, format_str);  // CRITICAL: format контролируется пользователем
}

// VULN 5: snprintf() с user-controlled format
void vuln_snprintf(char* user_format) {
    char output[512];
    snprintf(output, sizeof(output), user_format);  // CRITICAL
}

// VULN 6: vprintf() family
#include <stdarg.h>

void vuln_vprintf_wrapper(char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);  // MEDIUM-HIGH: format может быть от пользователя
    va_end(args);
}

void vuln_call_vprintf(char* user_input) {
    vuln_vprintf_wrapper(user_input);  // CRITICAL: передается user input
}

// VULN 7: syslog() с пользовательским сообщением
void vuln_syslog(char* user_msg) {
    syslog(LOG_INFO, user_msg);  // CRITICAL: syslog принимает format string
}

// VULN 8: printf() с environment variable
void vuln_printf_env() {
    char* user_lang = getenv("LANG");
    if (user_lang) {
        printf(user_lang);  // CRITICAL: env vars контролируются пользователем
    }
}

// VULN 9: fprintf() с данными из файла
void vuln_fprintf_file() {
    char format[256];
    FILE* f = fopen("/tmp/user_format.txt", "r");
    if (f) {
        fgets(format, sizeof(format), f);
        fprintf(stdout, format);  // CRITICAL: format из файла
        fclose(f);
    }
}

// VULN 10: Непрямой путь - через переменную
void vuln_indirect(char* input) {
    char* format = input;
    printf(format);  // CRITICAL: непрямое использование
}

// VULN 11: printf в цикле с user input
void vuln_loop(char** user_messages, int count) {
    for (int i = 0; i < count; i++) {
        printf(user_messages[i]);  // CRITICAL: каждое сообщение - format string
        printf("\n");
    }
}

// VULN 12: Комбинация с scanf
void vuln_scanf_printf() {
    char user_format[100];
    printf("Enter format: ");
    scanf("%99s", user_format);
    printf(user_format);  // CRITICAL: format от scanf
}

// VULN 13: dprintf() - newer function
void vuln_dprintf(int fd, char* user_msg) {
    dprintf(fd, user_msg);  // CRITICAL: dprintf также принимает format
}

// VULN 14: asprintf() - GNU extension
#ifdef _GNU_SOURCE
void vuln_asprintf(char* user_format) {
    char* buffer;
    asprintf(&buffer, user_format);  // CRITICAL
    free(buffer);
}
#endif

// VULN 15: Множественные printf с одним источником
void vuln_multiple_printf(char* msg) {
    printf(msg);         // CRITICAL
    fprintf(stderr, msg); // CRITICAL
    // Одна уязвимость используется дважды
}

int main(int argc, char** argv) {
    printf("Format String Vulnerability Examples\n");
    printf("DO NOT run with untrusted input!\n\n");

    // ДЕМОНСТРАЦИЯ (безопасно с константой):
    printf("Safe: This is a constant string\n");

    // Небезопасные примеры (закомментированы):
    // if (argc > 1) {
    //     vuln_printf_argv(argc, argv);  // ОПАСНО!
    // }

    vuln_indirect("AAA");
    vuln_syslog("AAA");
    vuln_snprintf("AA");

    return 0;
}
