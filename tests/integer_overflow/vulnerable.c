/*
 * Integer Overflow/Underflow - VULNERABLE examples
 *
 * Integer overflow может привести к:
 * - Неправильным проверкам размера → buffer overflow
 * - Выделению недостаточной памяти
 * - Логическим ошибкам в вычислениях
 *
 * Должны быть обнаружены с HIGH severity
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// VULN 1: Умножение без проверки переполнения
void vuln_multiply_overflow(int count, int size) {
    int total = count * size;  // HIGH: может переполниться
    char* buffer = malloc(total);
    if (buffer) {
        // Если произошло переполнение, выделится мало памяти
        memset(buffer, 0, total);
        free(buffer);
    }
}

// VULN 2: malloc() с умножением
void vuln_malloc_multiply(size_t num_items, size_t item_size) {
    void* ptr = malloc(num_items * item_size);  // CRITICAL: может переполниться
    // Если num_items * item_size > SIZE_MAX, выделится мало памяти
    free(ptr);
}

// VULN 3: Сложение без проверки
void vuln_addition(int a, int b) {
    int result = a + b;  // HIGH: может переполниться
    char* buffer = malloc(result);
    free(buffer);
}

// VULN 4: Вычитание с возможностью underflow
void vuln_subtraction(unsigned int total, unsigned int used) {
    unsigned int remaining = total - used;  // HIGH: может уйти в отрицательные
    // Если used > total, remaining будет огромным числом
    char* buffer = malloc(remaining);
    free(buffer);
}

// VULN 5: atoi() без проверки
void vuln_atoi(char* user_input) {
    int value = atoi(user_input);  // CRITICAL: может вернуть INT_MAX/INT_MIN
    // При переполнении возвращается неопределенное значение
    char* buffer = malloc(value);
    free(buffer);
}

// VULN 6: atol(), atoll() - тоже уязвимы
void vuln_atol(char* input) {
    long value = atol(input);  // CRITICAL: нет обработки ошибок
    if (value > 0) {
        malloc(value);  // Может быть переполнение
    }
}

// VULN 7: strtol() без проверки errno
void vuln_strtol_no_check(char* input) {
    long value = strtol(input, NULL, 10);  // HIGH: errno не проверяется
    // Если input слишком большой, вернется LONG_MAX, но errno не проверен
    malloc(value);
}

// VULN 8: Приведение типов с потерей данных
void vuln_type_conversion(long long big_value) {
    int small_value = (int)big_value;  // HIGH: может усечься
    malloc(small_value);
}

// VULN 9: Цикл с переполнением счетчика
void vuln_loop_overflow() {
    unsigned char i;
    for (i = 0; i < 300; i++) {  // BUG: unsigned char max = 255
        printf("%d ", i);  // Бесконечный цикл
    }
}

// VULN 10: Размер буфера вычисляется с переполнением
void vuln_buffer_size_calc(int width, int height) {
    int buffer_size = width * height * 4;  // HIGH: переполнение
    unsigned char* image = malloc(buffer_size);
    if (image) {
        memset(image, 0, buffer_size);
        free(image);
    }
}

// VULN 11: Проверка размера ПОСЛЕ вычисления
void vuln_check_after(int a, int b) {
    int result = a * b;  // Переполнение УЖЕ произошло
    if (result > 0) {    // Проверка бесполезна
        malloc(result);
    }
}

// VULN 12: Signed integer overflow в условии
void vuln_signed_overflow_condition(int user_value) {
    if (user_value + 100 > 0) {  // HIGH: переполнение в условии
        // Если user_value = INT_MAX, то user_value + 100 < 0
        printf("Safe zone\n");
    }
}

// VULN 13: calloc() с переполнением
void vuln_calloc(size_t count) {
    void* ptr = calloc(count, sizeof(int) * 100);  // HIGH: умножение до calloc
}

// VULN 14: realloc() с переполнением
void vuln_realloc(void* old_ptr, size_t old_size, size_t increment) {
    void* new_ptr = realloc(old_ptr, old_size + increment);  // HIGH: может переполниться
}

// VULN 15: Bitshift overflow
void vuln_bitshift(int value, int shift_amount) {
    int result = value << shift_amount;  // HIGH: может выйти за границы
    malloc(result);
}

// VULN 16: Множественное умножение
void vuln_multiple_multiply(int a, int b, int c) {
    int total = a * b * c;  // CRITICAL: несколько умножений
    malloc(total);
}

// VULN 17: Смешивание signed и unsigned
void vuln_mixed_signs(unsigned int u, int s) {
    unsigned int result = u + s;  // HIGH: signed может быть отрицательным
    malloc(result);
}

int main(int argc, char** argv) {
    printf("Integer Overflow Vulnerability Examples\n");
    printf("These SHOULD be detected by SentinelX\n\n");

    // Демонстрация overflow
    printf("INT_MAX = %d\n", INT_MAX);
    printf("INT_MAX + 1 = %d (overflow!)\n", INT_MAX + 1);

    // Небезопасные примеры (закомментированы):
    // vuln_multiply_overflow(1000000, 1000000);
    // if (argc > 1) vuln_atoi(argv[1]);

    return 0;
}
