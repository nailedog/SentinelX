/*
 * Format String - SAFE examples
 *
 * Правильное использование printf-подобных функций.
 * НЕ должны давать срабатывания или только LOW confidence.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>

// SAFE 1: printf() со строковым литералом
void safe_printf_literal() {
    printf("This is a safe constant string\n");  // SAFE: литерал
}

// SAFE 2: printf() с %s для пользовательского ввода
void safe_printf_with_format(char* user_input) {
    printf("%s\n", user_input);  // SAFE: format литерал, user_input как аргумент
}

// SAFE 3: printf() с множественными аргументами
void safe_printf_args(char* name, int age) {
    printf("Name: %s, Age: %d\n", name, age);  // SAFE: format строка литерал
}

// SAFE 4: fprintf() с правильным format
void safe_fprintf(char* message) {
    fprintf(stderr, "Error: %s\n", message);  // SAFE: format литерал
}

// SAFE 5: sprintf() с литеральным format
void safe_sprintf(char* username) {
    char buffer[256];
    sprintf(buffer, "Welcome, %s!", username);  // SAFE: format - константа
}

// SAFE 6: snprintf() - всегда с литеральным format
void safe_snprintf(char* name, char* email) {
    char output[512];
    snprintf(output, sizeof(output),
             "User: %s, Email: %s", name, email);  // SAFE
}

// SAFE 7: Использование константных format строк
const char* FORMAT_TEMPLATE = "User %s logged in at %s\n";

void safe_constant_format(char* user, char* time) {
    printf(FORMAT_TEMPLATE, user, time);  // SAFE: FORMAT_TEMPLATE - константа
}

// SAFE 8: vprintf с безопасным wrapper
void safe_log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);  // SAFE: format - const char* parameter
    va_end(args);
}

void safe_use_log(char* username) {
    safe_log("User %s connected\n", username);  // SAFE: format литерал
}

// SAFE 9: syslog() с правильным использованием
void safe_syslog(char* user_action) {
    syslog(LOG_INFO, "Action performed: %s", user_action);  // SAFE
}

// SAFE 10: fprintf в файл с format литералом
void safe_fprintf_file(FILE* logfile, char* event) {
    fprintf(logfile, "[LOG] %s\n", event);  // SAFE
}

// SAFE 11: Все спецификаторы в format строке
void safe_all_specifiers(char* str, int num, double flt) {
    printf("String: %s, Int: %d, Float: %.2f\n", str, num, flt);  // SAFE
}

// SAFE 12: Условный вывод с константными строками
void safe_conditional(int error_code, char* details) {
    if (error_code == 0) {
        printf("Success: %s\n", details);  // SAFE
    } else {
        fprintf(stderr, "Error %d: %s\n", error_code, details);  // SAFE
    }
}

// SAFE 13: printf в цикле с литеральным format
void safe_loop_print(char** items, int count) {
    for (int i = 0; i < count; i++) {
        printf("Item %d: %s\n", i, items[i]);  // SAFE: format константа
    }
}

// SAFE 14: Escape последовательности в format
void safe_escapes() {
    printf("Line 1\nLine 2\tTabbed\n");  // SAFE: escape sequences
}

// SAFE 15: Сложный format с множеством параметров
void safe_complex_format(char* name, int id, char* dept, double salary) {
    printf("Employee Record:\n"
           "  Name: %s\n"
           "  ID: %d\n"
           "  Department: %s\n"
           "  Salary: $%.2f\n",
           name, id, dept, salary);  // SAFE: многострочный литерал
}

// SAFE 16: dprintf() с правильным format
void safe_dprintf(int fd, char* message) {
    dprintf(fd, "Message: %s\n", message);  // SAFE
}

// SAFE 17: Макросы с безопасными format строками
#define LOG_INFO(msg) printf("[INFO] %s\n", msg)
#define LOG_ERROR(msg) fprintf(stderr, "[ERROR] %s\n", msg)

void safe_macros(char* info_msg, char* error_msg) {
    LOG_INFO(info_msg);    // SAFE: макрос использует литерал
    LOG_ERROR(error_msg);  // SAFE
}

// SAFE 18: Printf с проверенными данными
void safe_validated_input(char* input) {
    // Валидация: только буквы и цифры
    int valid = 1;
    for (char* p = input; *p; p++) {
        if (!isalnum(*p)) {
            valid = 0;
            break;
        }
    }

    if (valid) {
        printf("Safe input: %s\n", input);  // SAFE: данные проверены
    }
}

int main(int argc, char** argv) {
    printf("=== Safe Format String Examples ===\n\n");

    safe_printf_literal();
    safe_printf_with_format("Hello World");
    safe_printf_args("Alice", 30);
    safe_snprintf("Bob", "bob@example.com");

    if (argc > 1) {
        // Правильный способ вывода argv
        printf("Argument 1: %s\n", argv[1]);  // SAFE
    }

    printf("\nAll safe format string operations completed.\n");
    return 0;
}
