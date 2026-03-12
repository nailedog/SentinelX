/*
 * Race Condition - SAFE examples
 *
 * Правильная синхронизация для избежания race conditions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

// SAFE 1: Атомарное создание файла
void safe_atomic_create(const char* filename) {
    // O_EXCL гарантирует атомарность проверки и создания
    int fd = open(filename, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
        write(fd, "data", 4);
        close(fd);
    }  // SAFE: атомарная операция
}

// SAFE 2: mkstemp() вместо mktemp()
void safe_temp_file() {
    char tmpname[] = "/tmp/myapp_XXXXXX";
    int fd = mkstemp(tmpname);  // SAFE: атомарно создает файл
    if (fd >= 0) {
        write(fd, "temp", 4);
        close(fd);
        unlink(tmpname);
    }
}

// SAFE 3: Mutex для защиты shared данных
pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;
int safe_shared_counter = 0;

void* safe_thread_increment(void* arg) {
    for (int i = 0; i < 100000; i++) {
        pthread_mutex_lock(&counter_mutex);
        safe_shared_counter++;
        pthread_mutex_unlock(&counter_mutex);
    }  // SAFE: защищено mutex
    return NULL;
}

void safe_race_threads() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, safe_thread_increment, NULL);
    pthread_create(&t2, NULL, safe_thread_increment, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    // safe_shared_counter будет ровно 200000
}

// SAFE 4: Atomic operations (C11)
#include <stdatomic.h>

atomic_int safe_atomic_counter = 0;

void* safe_atomic_increment(void* arg) {
    for (int i = 0; i < 100000; i++) {
        atomic_fetch_add(&safe_atomic_counter, 1);
    }  // SAFE: атомарная операция
    return NULL;
}

// SAFE 5: Signal-safe функции в обработчике
volatile sig_atomic_t safe_signal_flag = 0;

void safe_signal_handler(int sig) {
    safe_signal_flag = 1;  // SAFE: sig_atomic_t безопасен
    // Не вызываем printf или другие небезопасные функции
}

// SAFE 6: File locking для критических секций
void safe_file_with_lock(const char* filename) {
    int fd = open(filename, O_RDWR);
    if (fd >= 0) {
        // Захватываем lock перед критической секцией
        struct flock fl = {
            .l_type = F_WRLCK,
            .l_whence = SEEK_SET,
            .l_start = 0,
            .l_len = 0
        };
        fcntl(fd, F_SETLKW, &fl);  // SAFE: эксклюзивный lock

        // Критическая секция
        write(fd, "protected", 9);

        // Освобождаем lock
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
        close(fd);
    }
}

int main() {
    printf("Safe synchronization examples\n");
    safe_temp_file();
    safe_atomic_create("test_atomic.txt");
    safe_race_threads();
    printf("Counter value: %d\n", safe_shared_counter);
    return 0;
}
