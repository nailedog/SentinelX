/*
 * Race Condition - VULNERABLE examples
 *
 * Race conditions возникают когда результат зависит
 * от порядка выполнения конкурирующих операций.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// VULN 1: TOCTOU (Time-of-check to time-of-use)
void vuln_toctou(const char* filename) {
    // Проверяем файл
    if (access(filename, W_OK) == 0) {
        // RACE: между access() и fopen() файл может измениться
        FILE* f = fopen(filename, "w");
        if (f) {
            fprintf(f, "data");
            fclose(f);
        }
    }
}

// VULN 2: Temporary file race
void vuln_temp_file() {
    char* tmpname = "/tmp/myapp_XXXXXX";
    // RACE: mktemp() только создает имя, не файл
    mktemp(tmpname);
    // Между mktemp() и open() злоумышленник может создать symlink
    int fd = open(tmpname, O_CREAT | O_WRONLY, 0600);
    close(fd);
}

// VULN 3: Общая переменная без синхронизации
#include <pthread.h>

int shared_counter = 0;  // Глобальная переменная

void* vuln_thread_increment(void* arg) {
    for (int i = 0; i < 100000; i++) {
        shared_counter++;  // RACE: не атомарно, не защищено
    }
    return NULL;
}

void vuln_race_threads() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, vuln_thread_increment, NULL);
    pthread_create(&t2, NULL, vuln_thread_increment, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    // shared_counter может быть < 200000 из-за race
}

// VULN 4: Signal handler с небезопасными функциями
volatile int signal_received = 0;

void vuln_signal_handler(int sig) {
    printf("Signal received\n");  // НЕ async-signal-safe!
    signal_received = 1;
}

// VULN 5: Проверка существования затем создание
void vuln_check_then_create(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        // RACE: между stat() и open() файл может появиться
        int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
        close(fd);
    }
}

int main() {
    printf("Race condition examples\n");
    return 0;
}
