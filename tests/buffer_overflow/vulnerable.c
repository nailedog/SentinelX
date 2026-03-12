/*
 * Buffer Overflow - VULNERABLE examples
 *
 * Эти примеры содержат реальные уязвимости переполнения буфера
 * и ДОЛЖНЫ быть обнаружены SentinelX с HIGH/CRITICAL severity
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// VULN 1: gets() - всегда уязвимо
void vuln_gets() {
    char buffer[100];
    printf("Enter name: ");
    gets(buffer);  // CRITICAL: gets() не проверяет границы
}

// VULN 2: strcpy() с пользовательским вводом
void vuln_strcpy_argv(int argc, char** argv) {
    char buffer[50];
    if (argc > 1) {
        strcpy(buffer, argv[1]);  // CRITICAL: argv[1] может быть любого размера
    }
}

// VULN 3: strcpy() с неизвестным источником
void vuln_strcpy_param(char* user_input) {
    char dest[100];
    strcpy(dest, user_input);  // HIGH: размер user_input неизвестен
}

// VULN 4: strcat() с пользовательским вводом
void vuln_strcat(int argc, char** argv) {
    char buffer[100] = "Hello ";
    if (argc > 1) {
        strcat(buffer, argv[1]);  // CRITICAL: может переполнить буфер
    }
}

// VULN 5: sprintf() без проверки размера
void vuln_sprintf(char* username) {
    char message[50];
    sprintf(message, "Welcome, %s!", username);  // HIGH: username может быть слишком длинным
}

// VULN 6: scanf() с неограниченным %s
void vuln_scanf() {
    char input[50];
    scanf("%s", input);  // HIGH: %s читает неограниченно
}

// VULN 7: Множественное копирование может переполнить
void vuln_multiple_copy() {
    char buf[100];
    char part1[60] = "This is a very long string part one";
    char part2[60] = "This is a very long string part two";

    strcpy(buf, part1);
    strcat(buf, part2);  // CRITICAL: 60+60 > 100
}

// VULN 8: Копирование из environment variable
void vuln_env() {
    char buffer[100];
    char* path = getenv("PATH");
    if (path) {
        strcpy(buffer, path);  // HIGH: PATH может быть очень длинным
    }
}

// VULN 9: Чтение из файла без проверки
void vuln_file_read() {
    char buffer[256];
    FILE* f = fopen("input.txt", "r");
    if (f) {
        fgets(buffer, 1024, f);  // CRITICAL: читает 1024 в буфер размером 256
        fclose(f);
    }
}

// VULN 10: Вложенные функции
void copy_data(char* dest, char* src) {
    strcpy(dest, src);  // HIGH: размеры неизвестны
}

void vuln_nested(char* user_data) {
    char local_buf[50];
    copy_data(local_buf, user_data);  // HIGH: может переполнить local_buf
}

int main(int argc, char** argv) {
    printf("Buffer Overflow Vulnerability Examples\n");
    printf("These examples SHOULD be detected by SentinelX\n\n");

    // Раскомментируйте для тестирования:
    vuln_gets();
    vuln_strcpy_argv(argc, argv);
    vuln_scanf();
    vuln_nested("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    vuln_sprintf("run");
    vuln_multiple_copy();
    vuln_sprintf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    return 0;
}
