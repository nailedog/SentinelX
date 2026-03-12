/*
 * Buffer Overflow - SAFE examples (False Positive tests)
 *
 * Эти примеры используют потенциально опасные функции,
 * но делают это БЕЗОПАСНО. SentinelX должен показывать
 * LOW confidence или не показывать их вообще.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// SAFE 1: strcpy() с константой, буфер достаточно большой
void safe_strcpy_constant() {
    char buffer[100];
    strcpy(buffer, "Hello World");  // SAFE: "Hello World" = 12 байт, буфер = 100
}

// SAFE 2: strcpy() когда dest больше src
void safe_strcpy_known_sizes() {
    char large_buffer[200];
    char small_source[50] = "Small string";
    strcpy(large_buffer, small_source);  // SAFE: 200 > 50
}

// SAFE 3: Использование безопасных альтернатив
void safe_strncpy(char* input) {
    char buffer[100];
    strncpy(buffer, input, sizeof(buffer) - 1);  // SAFE: ограничен размером
    buffer[sizeof(buffer) - 1] = '\0';
}

// SAFE 4: scanf() с ограничением ширины
void safe_scanf() {
    char input[50];
    scanf("%49s", input);  // SAFE: максимум 49 символов + \0
}

// SAFE 5: sprintf() с достаточно большим буфером
void safe_sprintf() {
    char buffer[100];
    char name[10] = "Alice";
    sprintf(buffer, "Hello, %s!", name);  // SAFE: "Hello, " + 10 + "!" < 100
}

// SAFE 6: Проверка размера перед копированием
void safe_with_validation(char* input) {
    char buffer[100];
    if (strlen(input) < sizeof(buffer)) {
        strcpy(buffer, input);  // SAFE: проверен размер
    }
}

// SAFE 7: Использование snprintf() - автоматически безопасно
void safe_snprintf(char* name, char* email) {
    char message[256];
    snprintf(message, sizeof(message),
             "User: %s, Email: %s", name, email);  // SAFE: ограничен размером
}

// SAFE 8: fgets() с правильным размером
void safe_fgets() {
    char buffer[256];
    FILE* f = fopen("input.txt", "r");
    if (f) {
        fgets(buffer, sizeof(buffer), f);  // SAFE: размер совпадает
        fclose(f);
    }
}

// SAFE 9: strlcpy() - BSD безопасная функция
#ifdef __BSD__
void safe_strlcpy(char* input) {
    char buffer[100];
    strlcpy(buffer, input, sizeof(buffer));  // SAFE: BSD функция с размером
}
#endif

// SAFE 10: Динамическая память с правильным размером
void safe_dynamic(char* input) {
    size_t len = strlen(input);
    char* buffer = malloc(len + 1);  // SAFE: точный размер
    if (buffer) {
        strcpy(buffer, input);
        // ... использование ...
        free(buffer);
    }
}

// SAFE 11: Копирование из известного безопасного источника
void safe_hardcoded_array() {
    const char* safe_strings[] = {
        "Option 1",
        "Option 2",
        "Option 3"
    };
    char buffer[50];

    // Все строки заведомо короткие
    strcpy(buffer, safe_strings[0]);  // SAFE: известный размер
}

// SAFE 12: Проверка индекса и размера
void safe_bounded_copy(char** strings, int index, int max_len) {
    char buffer[100];
    if (index >= 0 && index < 10 && max_len < 100) {
        strncpy(buffer, strings[index], max_len);  // SAFE: все проверено
        buffer[max_len] = '\0';
    }
}

// SAFE 13: memcpy с точным размером
void safe_memcpy() {
    char src[50] = "Source data";
    char dst[100];
    memcpy(dst, src, sizeof(src));  // SAFE: src <= dst
}

// SAFE 14: Использование безопасных библиотек C++
#ifdef __cplusplus
#include <string>

void safe_cpp_string(const char* input) {
    std::string buffer = input;  // SAFE: std::string управляет размером
    // ...
}
#endif

int main() {
    printf("Safe Buffer Operations Examples\n");
    printf("These should NOT trigger or have LOW confidence\n\n");

    safe_strcpy_constant();
    safe_scanf();
    safe_snprintf("Alice", "alice@example.com");

    printf("All safe operations completed successfully.\n");
    return 0;
}
