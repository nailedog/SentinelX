# SentinelX

**SentinelX** — статический анализатор безопасности для бинарных файлов и исходного кода на C/C++. Инструмент обнаруживает уязвимости (buffer overflow, format string, integer overflow и другие), строит граф вызовов, выполняет taint-анализ и автоматически генерирует PoC-эксплойты для найденных уязвимостей.

---

## О проекте

SentinelX объединяет анализ исходного кода и бинарных файлов в одном инструменте:

- **Source analysis** — парсинг C/C++ кода, поиск опасных вызовов, анализ потоков данных
- **Binary analysis** — дизассемблирование ELF/PE/MachO через LIEF + Capstone, обнаружение уязвимостей в скомпилированных бинарях
- **Exploit generation** — автоматическое создание PoC-скриптов (Python/C) с шеллкодом и ROP-цепочками
- **CWE integration** — каждая уязвимость сопоставляется с базой CVE/CWE (SQLite3)
- **VSCode extension** — интеграция результатов анализа прямо в редактор

---

## Архитектура

```
SentinelX
├── src/
│   ├── main.cpp                    # Точка входа, CLI-парсер
│   ├── analyzer.cpp                # Главный координатор анализа
│   ├── binary_parser.cpp           # Парсинг ELF/PE/MachO (LIEF)
│   ├── disassembler.cpp            # Дизассемблер (Capstone)
│   ├── detectors.cpp               # Детекторы уязвимостей (source)
│   ├── fsm.cpp                     # FSM-машина для паттерн-матчинга
│   ├── call_graph.cpp              # Построение графа вызовов
│   ├── call_site_analyzer.cpp      # Анализ точек вызова
│   ├── stack_analyzer.cpp          # Анализ стека
│   ├── arithmetic_analyzer.cpp     # Анализ арифметических операций
│   ├── buffer_analysis.cpp         # Анализ работы с буферами
│   ├── taint_analysis.cpp          # Taint-анализ (отслеживание данных)
│   ├── json_output.cpp             # JSON-репортинг
│   ├── utils.cpp                   # Утилиты
│   ├── exploit_engine.cpp          # Главный движок генерации эксплойтов
│   ├── shellcode_generator.cpp     # Генератор шеллкода (x86/x64/ARM)
│   ├── gadget_finder.cpp           # Поиск ROP-гаджетов
│   ├── rop_builder.cpp             # Построитель ROP-цепочек
│   ├── exploit_templates.cpp       # Шаблоны эксплойтов (Python/C)
│   ├── core/
│   │   └── orchestrator.cpp        # AnalysisOrchestrator (новая архитектура)
│   ├── cwe/
│   │   ├── cwe_repository.cpp      # Репозиторий CWE (SQLite3)
│   │   └── cwe_schema.sql          # SQL-схема базы CWE
│   └── detectors/
│       └── buffer_overflow_detector.cpp  # Модульный детектор (новая архитектура)
│
├── include/
│   ├── analyzer.h
│   ├── binary_parser.h
│   ├── disassembler.h
│   ├── detectors.h
│   ├── fsm.h / fsm.hpp
│   ├── types.h                     # Основные типы (Finding, Severity, Confidence)
│   ├── exploit_engine.h
│   ├── exploit_types.h
│   ├── shellcode_generator.h
│   ├── gadget_finder.h
│   ├── rop_builder.h
│   ├── exploit_templates.h
│   ├── call_graph.h
│   ├── taint_analysis.h
│   ├── stack_analyzer.h
│   ├── arithmetic_analyzer.h
│   ├── buffer_analysis.h
│   ├── call_site_analyzer.h
│   ├── json_output.hpp
│   └── report.hpp
│
├── LIEF/                           # Встроенная библиотека (git submodule)
├── data/cwe/cwe_database.db        # База данных CWE (SQLite3)
├── tests/                          # Тестовые C-программы (safe/vulnerable)
├── examples/                       # Примеры использования API
├── docker/                         # Docker-конфигурация
├── vscode-extension/               # VSCode плагин (TypeScript)
├── CMakeLists.txt
├── build.sh
└── Dockerfile
```

### Поток данных

```
Входные файлы (source / binary)
         │
         ▼
    Analyzer (analyzer.cpp)
    ┌──────────────────────────────────────┐
    │  Source path          Binary path    │
    │      │                    │          │
    │  Detectors            BinaryParser   │
    │  (FSM + patterns)     (LIEF)         │
    │      │                    │          │
    │  CallGraph            Disassembler   │
    │  TaintAnalysis        (Capstone)     │
    │  StackAnalyzer             │         │
    │  ArithmeticAnalyzer        │         │
    │      │                    │          │
    │      └────────┬───────────┘          │
    │               ▼                      │
    │          Findings[]                  │
    │          + CWE enrichment            │
    └──────────────────────────────────────┘
               │
    ┌──────────┴────────────┐
    │                       │
    ▼                       ▼
 Text/JSON output     ExploitEngine
                      ┌────────────────┐
                      │ ShellcodeGen   │
                      │ GadgetFinder   │
                      │ RopBuilder     │
                      │ ExploitTemplates│
                      └────────────────┘
                           │
                      Python/C exploits
```

---

## Обнаруживаемые уязвимости

| ID | Уязвимость | CWE | Источник |
|----|------------|-----|---------|
| `BIN_UNSAFE_CALL_strcpy` | Небезопасный вызов strcpy | CWE-120 | Source + Binary |
| `BIN_UNSAFE_CALL_gets` | Небезопасный вызов gets | CWE-120 | Source + Binary |
| `BIN_UNSAFE_CALL_sprintf` | Небезопасный sprintf | CWE-120 | Source + Binary |
| `BIN_UNSAFE_CALL_printf` | Format string уязвимость | CWE-134 | Source + Binary |
| `BIN_STACK_BUFFER_OVERFLOW` | Переполнение стекового буфера | CWE-787 | Binary |
| `BIN_INTEGER_OVERFLOW` | Целочисленное переполнение | CWE-190 | Source + Binary |
| `BIN_USE_AFTER_FREE` | Use-after-free | CWE-416 | Source |
| `BIN_COMMAND_INJECTION` | Внедрение команд | CWE-78 | Source |
| `BIN_RACE_CONDITION` | Состояние гонки | CWE-362 | Source |

---

## Зависимости

### Обязательные

| Библиотека | Версия | Назначение |
|-----------|--------|-----------|
| **CMake** | ≥ 3.15 | Система сборки |
| **GCC / Clang** | C++17 | Компилятор |
| **LIEF** | встроена (submodule) | Парсинг ELF/PE/MachO бинарей |
| **SQLite3** | системная | База данных CWE |

### Опциональные

| Библиотека | Назначение |
|-----------|-----------|
| **Capstone** | Дизассемблирование (используется через LIEF) |
| **Node.js + npm** | Сборка VSCode-расширения |

### Установка зависимостей

**macOS (Homebrew):**
```bash
brew install cmake sqlite3
```

**Ubuntu / Debian:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libsqlite3-dev
```

**Fedora / RHEL:**
```bash
sudo dnf install cmake gcc-c++ sqlite-devel
```

---

## Установка и сборка

### 1. Клонирование репозитория

```bash
git clone --recurse-submodules https://github.com/nailedog/SentinelX.git
cd SentinelX
```

> Флаг `--recurse-submodules` необходим для загрузки LIEF.

Если забыли флаг:
```bash
git submodule update --init --recursive
```

### 2. Сборка (скрипт)

```bash
chmod +x build.sh
./build.sh
```

### 3. Сборка вручную (CMake)

```bash
mkdir build && cd build
cmake .. -DSENTINELX_USE_LIEF=ON -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### 4. Сборка без LIEF (только source-анализ)

```bash
cmake .. -DSENTINELX_USE_LIEF=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

Бинарный файл: `build/SentinelX`

---

## Использование

### Базовый анализ

```bash
# Анализ исходного кода
./build/SentinelX --source ./src

# Анализ бинарного файла
./build/SentinelX --binary ./a.out

# Совместный анализ
./build/SentinelX --source ./src --binary ./a.out

# JSON-вывод
./build/SentinelX --source ./src --json
```

### Фильтрация по уровню доверия

```bash
./build/SentinelX --source ./src --min-confidence HIGH
# Уровни: LOW | MEDIUM | HIGH | CERTAIN
```

### Фильтрация по достижимости функций

```bash
# Только уязвимости в функциях, достижимых из main (по умолчанию)
./build/SentinelX --binary ./a.out --only-reachable

# Все функции
./build/SentinelX --binary ./a.out --all-functions
```

### Генерация эксплойтов

```bash
# Python-эксплойт
./build/SentinelX --binary ./vuln --generate-exploits

# Python + C эксплойт
./build/SentinelX --binary ./vuln --generate-exploits --exploit-format both

# Указать директорию вывода
./build/SentinelX --binary ./vuln --generate-exploits --exploit-output ./my_exploits

# Без шеллкода и ROP
./build/SentinelX --binary ./vuln --generate-exploits --no-shellcode --no-rop
```

### Дизассемблирование

```bash
# Дизассемблировать конкретную функцию
./build/SentinelX --binary ./vuln --disas main

# Интерактивный режим
./build/SentinelX --binary ./vuln --interactive
# Команды: disas <func>, info functions, help, quit
```

---

## Docker

```bash
# Сборка образа
docker build -t sentinelx .

# Анализ бинарного файла
docker run --rm -v $(pwd):/data sentinelx --binary /data/your_binary

# Анализ исходников
docker run --rm -v $(pwd):/data sentinelx --source /data/src

# docker-compose
cd docker && docker-compose up
```

---

## VSCode Extension

Расширение добавляет результаты анализа прямо в редактор в виде диагностик.

```bash
cd vscode-extension
npm install
npm run compile

# Установка .vsix файла
code --install-extension sentinelx-1.0.0.vsix
```

Подробнее: [vscode-extension/README.md](vscode-extension/README.md)

---

## Опции CMake

| Опция | По умолчанию | Описание |
|-------|-------------|---------|
| `SENTINELX_USE_LIEF` | ON | Бинарный анализ через LIEF |
| `SENTINELX_ENABLE_CWE` | ON | Интеграция базы CWE (SQLite3) |
| `SENTINELX_BUILD_EXAMPLES` | ON | Сборка примеров |
| `SENTINELX_ENABLE_PLUGINS` | OFF | Система плагинов (в разработке) |
| `SENTINELX_ENABLE_DSL` | OFF | DSL движок правил (в разработке) |
| `SENTINELX_ENABLE_AI` | OFF | AI-интеграция (в разработке) |

---

## Взаимосвязи компонентов

```
main.cpp
 ├── Analyzer               ← центральный координатор
 │    ├── Detectors         ← паттерны опасных вызовов (source)
 │    │    └── FSM          ← конечный автомат для паттернов
 │    ├── BinaryParser      ← LIEF: ELF/PE/MachO заголовки + символы
 │    │    └── Disassembler ← Capstone: инструкции + dangerous flags
 │    ├── CallGraph         ← граф вызовов для фильтрации
 │    ├── TaintAnalysis     ← отслеживание небезопасных данных
 │    ├── StackAnalyzer     ← размеры буферов на стеке
 │    ├── ArithmeticAnalyzer← переполнение целых чисел
 │    ├── BufferAnalysis    ← размерный анализ буферов
 │    ├── CallSiteAnalyzer  ← анализ аргументов в точках вызова
 │    └── CweRepository     ← SQLite3: обогащение findings CWE-данными
 │
 ├── ExploitEngine          ← оркестратор генерации эксплойтов
 │    ├── ShellcodeGenerator← шеллкоды x86/x64/ARM
 │    ├── GadgetFinder      ← поиск ROP-гаджетов в бинаре
 │    ├── RopBuilder        ← сборка ROP-цепочек
 │    └── ExploitTemplates  ← рендеринг Python/C шаблонов
 │
 └── JsonOutput / Report    ← форматирование вывода
```

---

## Тестирование

В директории `tests/` содержатся пары файлов `safe.c` / `vulnerable.c` для каждой категории уязвимостей:

```bash
# Компиляция тестов
gcc -o tests/buffer_overflow/vulnerable tests/buffer_overflow/vulnerable.c

# Запуск анализа тестов
./build/SentinelX --source tests/buffer_overflow/vulnerable.c
./build/SentinelX --binary tests/buffer_overflow/vulnerable

# Запуск всех тестов
chmod +x run_all_tests.sh
./run_all_tests.sh
```

---

## Будущие расширения

### Phase 2 — Параллельный анализ
- Многопоточное выполнение детекторов (`std::async` / thread pool)
- Кэширование результатов разбора бинарей
- Инкрементальный анализ (только изменённые файлы)

### Phase 3 — Система плагинов
- Динамическая загрузка детекторов (`.so` / `.dll`)
- Plugin SDK с документированным API (`IDetector` interface)
- Маркетплейс сторонних детекторов

### Phase 4 — DSL движок правил
- YAML/TOML правила для собственных паттернов
- Компилятор DSL в эффективный матчер
- Горячая перезагрузка правил без перекомпиляции

### Phase 5 — AI интеграция
- LLM-объяснения для каждой уязвимости
- AI-подсказки для эксплойтов
- Локальный инференс (llama.cpp / ONNX)
- RAG по базе CVE для контекстуализации

### Прочее
- SARIF-вывод для CI/CD интеграции (GitHub Code Scanning)
- Web UI с визуализацией графа вызовов
- Поддержка Rust и Go бинарей
- Интеграция с GDB/LLDB для динамической верификации

---

## Лицензия

Проект предназначен исключительно для **образовательных целей** и **авторизованного тестирования безопасности**. Использование в отношении систем без явного разрешения владельца запрещено.
