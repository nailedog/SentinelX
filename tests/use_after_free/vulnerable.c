/*
 * Use After Free - VULNERABLE examples
 *
 * Use-after-free возникает когда память освобождена (free),
 * но программа продолжает использовать указатель на неё.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// VULN 1: Классический use-after-free
void vuln_classic_uaf() {
    char* ptr = malloc(100);
    strcpy(ptr, "Hello");
    free(ptr);
    printf("%s\n", ptr);  // UAF: использование после free
}

// VULN 2: Double free
void vuln_double_free() {
    char* ptr = malloc(50);
    free(ptr);
    free(ptr);  // CRITICAL: повторное освобождение
}

// VULN 3: Use after free в условии
void vuln_uaf_conditional(int condition) {
    int* data = malloc(sizeof(int) * 10);
    if (condition) {
        free(data);
    }
    data[0] = 42;  // UAF если condition == true
}

// VULN 4: Использование через другой указатель
void vuln_uaf_alias() {
    char* ptr1 = malloc(100);
    char* ptr2 = ptr1;
    free(ptr1);
    strcpy(ptr2, "data");  // UAF: ptr2 указывает на освобожденную память
}

// VULN 5: UAF в структуре
struct Data {
    char* buffer;
    int size;
};

void vuln_uaf_struct() {
    struct Data* d = malloc(sizeof(struct Data));
    d->buffer = malloc(50);
    free(d->buffer);
    strcpy(d->buffer, "text");  // UAF
    free(d);
}

// VULN 6: Возврат освобожденного указателя
char* vuln_return_freed() {
    char* local = malloc(100);
    strcpy(local, "data");
    free(local);
    return local;  // CRITICAL: возврат freed указателя
}

int main() {
    printf("Use-After-Free examples (DO NOT RUN)\n");
    return 0;
}
