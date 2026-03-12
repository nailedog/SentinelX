/*
 * Use After Free - SAFE examples
 *
 * Правильное управление памятью без UAF проблем.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// SAFE 1: Использование перед free
void safe_use_before_free() {
    char* ptr = malloc(100);
    strcpy(ptr, "Hello");
    printf("%s\n", ptr);
    free(ptr);  // SAFE: free после использования
}

// SAFE 2: Обнуление указателя после free
void safe_nullify_after_free() {
    char* ptr = malloc(100);
    strcpy(ptr, "data");
    free(ptr);
    ptr = NULL;  // SAFE: предотвращает повторное использование
    if (ptr != NULL) {
        printf("%s\n", ptr);
    }
}

// SAFE 3: Правильная очистка структуры
struct Data {
    char* buffer;
    int size;
};

void safe_struct_cleanup() {
    struct Data* d = malloc(sizeof(struct Data));
    d->buffer = malloc(50);
    strcpy(d->buffer, "text");

    // Правильный порядок освобождения
    free(d->buffer);
    d->buffer = NULL;
    free(d);  // SAFE: buffer уже freed
}

// SAFE 4: RAII pattern (если используется C++)
#ifdef __cplusplus
class SafeBuffer {
    char* data;
public:
    SafeBuffer(size_t size) : data(new char[size]) {}
    ~SafeBuffer() { delete[] data; }  // SAFE: автоматическое освобождение
    char* get() { return data; }
};
#endif

// SAFE 5: Использование scope для управления временем жизни
void safe_scoped_allocation() {
    {
        char* ptr = malloc(100);
        strcpy(ptr, "scoped");
        printf("%s\n", ptr);
        free(ptr);
        // ptr выходит из области видимости
    }
    // Здесь ptr недоступен - нет риска UAF
}

int main() {
    safe_use_before_free();
    safe_nullify_after_free();
    safe_struct_cleanup();
    printf("Safe memory management completed\n");
    return 0;
}
