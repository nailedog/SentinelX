/*
 * Integer Overflow - SAFE examples
 *
 * Правильная обработка целочисленных операций с проверками.
 * Должны показывать LOW confidence или не показываться.
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>

void safe_multiply_check(int a, int b) {
    if (a > 0 && b > 0 && a > INT_MAX / b) {
        fprintf(stderr, "Multiplication would overflow\n");
        return;
    }
    int result = a * b;  // SAFE: проверено
    malloc(result);
}

// SAFE 2: Использование SIZE_MAX для проверки
void safe_malloc_size_check(size_t count, size_t size) {
    if (count > 0 && size > SIZE_MAX / count) {
        fprintf(stderr, "Allocation too large\n");
        return;
    }
    void* ptr = malloc(count * size);  // SAFE: проверено
    free(ptr);
}

// SAFE 3: strtol() с проверкой errno
void safe_strtol(char* input) {
    char* endptr;
    errno = 0;
    long value = strtol(input, &endptr, 10);

    if (errno == ERANGE || *endptr != '\0') {
        fprintf(stderr, "Invalid number or overflow\n");
        return;
    }

    if (value > 0 && value < SIZE_MAX) {
        malloc(value);  // SAFE: проверено
    }
}

// SAFE 4: Использование builtin функций GCC/Clang
#if __GNUC__ >= 5 || __clang__
void safe_builtin_multiply(int a, int b) {
    int result;
    if (__builtin_mul_overflow(a, b, &result)) {
        fprintf(stderr, "Multiplication overflow detected\n");
        return;
    }
    malloc(result);  // SAFE: overflow обнаружен
}

void safe_builtin_add(int a, int b) {
    int result;
    if (__builtin_add_overflow(a, b, &result)) {
        fprintf(stderr, "Addition overflow\n");
        return;
    }
    malloc(result);  // SAFE
}
#endif

// SAFE 5: Константные значения - нет overflow
void safe_constants() {
    int size = 100 * 50;  // SAFE: 5000, известно что не переполнится
    malloc(size);
}

// SAFE 6: Проверка диапазона входных данных
void safe_range_check(int user_value) {
    if (user_value < 0 || user_value > 10000) {
        fprintf(stderr, "Value out of safe range\n");
        return;
    }
    int doubled = user_value * 2;  // SAFE: max = 20000
    malloc(doubled);
}

// SAFE 7: Использование saturating arithmetic
int safe_saturating_add(int a, int b) {
    if (a > 0 && b > INT_MAX - a) {
        return INT_MAX;  // Насыщение вместо переполнения
    }
    if (a < 0 && b < INT_MIN - a) {
        return INT_MIN;
    }
    return a + b;  // SAFE
}

// SAFE 8: calloc() вместо malloc(a*b)
void safe_use_calloc(size_t count, size_t size) {
    // calloc() внутренне проверяет переполнение
    void* ptr = calloc(count, size);  // SAFE: calloc проверяет
    if (!ptr) {
        fprintf(stderr, "Allocation failed\n");
    }
    free(ptr);
}

// SAFE 9: Использование uint64_t для промежуточных вычислений
void safe_large_multiply(uint32_t a, uint32_t b) {
    uint64_t result = (uint64_t)a * (uint64_t)b;  // SAFE: больший тип
    if (result > UINT32_MAX) {
        fprintf(stderr, "Result too large\n");
        return;
    }
    malloc((uint32_t)result);
}

// SAFE 10: Проверка вычитания unsigned
void safe_unsigned_subtract(unsigned int total, unsigned int used) {
    if (used > total) {
        fprintf(stderr, "Underflow would occur\n");
        return;
    }
    unsigned int remaining = total - used;  // SAFE: проверено
    malloc(remaining);
}

// SAFE 11: Ограничение размера перед умножением
#define MAX_ITEMS 1000
#define MAX_SIZE 1000

void safe_bounded_allocation(int items, int size) {
    if (items < 0 || items > MAX_ITEMS ||
        size < 0 || size > MAX_SIZE) {
        fprintf(stderr, "Values out of bounds\n");
        return;
    }
    int total = items * size;  // SAFE: ограничено константами
    malloc(total);
}

// SAFE 12: Проверка результата atoi
void safe_atoi_check(char* input) {
    int value = atoi(input);
    if (value <= 0 || value > 1000000) {
        fprintf(stderr, "Invalid value from atoi\n");
        return;
    }
    malloc(value);  // SAFE: проверен диапазон
}

// SAFE 13: Использование безопасных библиотек
#ifdef USE_SAFE_INT
#include "safe_int.h"  // Гипотетическая библиотека

void safe_library_multiply(int a, int b) {
    int result;
    if (safe_int_multiply(&result, a, b) != SAFE_INT_OK) {
        fprintf(stderr, "Overflow\n");
        return;
    }
    malloc(result);  // SAFE: библиотека проверила
}
#endif

// SAFE 14: Проверка переполнения сложения
void safe_add_check(unsigned int a, unsigned int b) {
    if (a > UINT_MAX - b) {
        fprintf(stderr, "Addition overflow\n");
        return;
    }
    unsigned int sum = a + b;  // SAFE
    malloc(sum);
}

// SAFE 15: Использование SIZE_MAX корректно
void safe_size_max_check(size_t requested_size) {
    if (requested_size == 0 || requested_size > SIZE_MAX / 2) {
        fprintf(stderr, "Invalid size\n");
        return;
    }
    void* ptr = malloc(requested_size);  // SAFE
    free(ptr);
}

// SAFE 16: Проверка типов перед приведением
void safe_type_cast(long long big_value) {
    if (big_value > INT_MAX || big_value < INT_MIN) {
        fprintf(stderr, "Value doesn't fit in int\n");
        return;
    }
    int small_value = (int)big_value;  // SAFE: проверено
    malloc(small_value);
}

// SAFE 17: Использование assert для проверки (debug mode)
#include <assert.h>

void safe_with_assert(int a, int b) {
    assert(a > 0 && a < 1000);
    assert(b > 0 && b < 1000);
    int result = a * b;  // SAFE: assert проверит в debug
    malloc(result);
}

int main() {
    printf("=== Safe Integer Operations ===\n\n");

    safe_constants();
    safe_range_check(100);
    safe_use_calloc(10, sizeof(int));
    safe_strtol("12345");

    printf("All safe integer operations completed.\n");
    return 0;
}
