# 🎯 SentinelX Integration с VS Code

## Обзор

Интеграция SentinelX с VS Code позволяет видеть уязвимости безопасности **прямо в редакторе** с желтым/красным подчеркиванием при наборе или сохранении кода.

## Возможности

✅ **Real-time анализ** - Обнаружение уязвимостей при наборе или сохранении файла
✅ **Визуальные индикаторы** - Цветное подчеркивание кода (красное/желтое/синее)
✅ **Problems панель** - Интеграция со стандартной панелью проблем VS Code
✅ **Hover подсказки** - Детальная информация при наведении курсора
✅ **Workspace анализ** - Сканирование всего проекта одной командой
✅ **Настраиваемые уровни** - Фильтрация по severity и confidence
✅ **Output логи** - Детальные логи анализа в реальном времени

## Что было создано

```
vscode-extension/
├── src/
│   └── extension.ts          # Основная логика расширения
├── .vscode/
│   ├── launch.json           # Конфигурация для отладки
│   └── tasks.json            # Задачи сборки
├── package.json              # Манифест расширения
├── tsconfig.json             # Конфигурация TypeScript
├── .eslintrc.json            # Правила линтера
├── .gitignore                # Игнорируемые файлы
├── .vscodeignore             # Файлы, не включаемые в пакет
├── README.md                 # Основная документация
├── INSTALLATION.md           # Детальная инструкция установки
├── QUICKSTART.md             # Быстрый старт за 5 минут
└── CHANGELOG.md              # История изменений
```

## Быстрый старт

### 1. Установка зависимостей и компиляция

```bash
cd /Users/gen/Desktop/Projects/SentinelX/V-1.0/vscode-extension
npm install
npm run compile
```

### 2. Запуск в режиме разработки

```bash
code .
# Затем нажмите F5 в VS Code
```

Откроется новое окно "Extension Development Host" для тестирования.

### 3. Тестирование

Создайте файл `test.c`:

```c
#include <string.h>

void test(char *input) {
    char buffer[16];
    strcpy(buffer, input);  // Будет подчеркнуто красным!
}
```

Сохраните файл (**Cmd+S**) и увидите подчеркивание.

## Настройка

### Конфигурация в settings.json

```json
{
  "sentinelx.enabled": true,
  "sentinelx.executablePath": "/Users/gen/Desktop/Projects/SentinelX/V-1.0/build/SentinelX",
  "sentinelx.analyzeOnSave": true,
  "sentinelx.analyzeOnType": false,
  "sentinelx.minConfidence": "MEDIUM",
  "sentinelx.showInfoSeverity": false,
  "sentinelx.debounceTime": 500
}
```

### Параметры

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `enabled` | boolean | `true` | Включить/выключить расширение |
| `executablePath` | string | `""` | Путь к SentinelX (оставьте пустым для PATH) |
| `analyzeOnSave` | boolean | `true` | Анализ при сохранении файла |
| `analyzeOnType` | boolean | `false` | Анализ при наборе (может влиять на производительность) |
| `minConfidence` | string | `"MEDIUM"` | Минимальный уровень confidence (LOW/MEDIUM/HIGH/CERTAIN) |
| `showInfoSeverity` | boolean | `false` | Показывать INFO уровень |
| `debounceTime` | number | `500` | Задержка для on-type анализа (мс) |

## Команды

Доступные команды (вызов через **Cmd+Shift+P** или **Ctrl+Shift+P**):

1. **SentinelX: Analyze Current File** - Анализ текущего открытого файла
2. **SentinelX: Analyze Whole Workspace** - Анализ всего проекта
3. **SentinelX: Clear All Diagnostics** - Очистить все предупреждения

## Визуальные индикаторы

### Подчеркивание в коде

- 🔴 **Красная волнистая линия** - CRITICAL/HIGH severity
- 🟡 **Желтая волнистая линия** - WARNING severity
- 🔵 **Синяя волнистая линия** - INFO severity

### Панель Problems

Откройте панель проблем: **View → Problems** или **Cmd+Shift+M** / **Ctrl+Shift+M**

Вы увидите список всех уязвимостей с:
- Иконкой severity (❌ ⚠️ ℹ️)
- Названием файла и номером строки
- Кратким описанием проблемы
- Возможностью клика для перехода к коду

### Hover (всплывающая подсказка)

При наведении курсора на подчеркнутый код отображается:
```
[CRITICAL][HIGH] Call to potentially unsafe function 'strcpy'
without explicit bounds. (in test)
```

## Режимы работы

### Режим 1: Анализ при сохранении (рекомендуется)

**Преимущества:**
- Не влияет на производительность при наборе
- Анализ только синтаксически корректного кода
- Идеально для ежедневной разработки

**Настройка:**
```json
{
  "sentinelx.analyzeOnSave": true,
  "sentinelx.analyzeOnType": false
}
```

### Режим 2: Анализ при наборе (экспериментальный)

**Преимущества:**
- Мгновенная обратная связь
- Видите проблемы сразу при написании кода

**Недостатки:**
- Может замедлить редактор на больших файлах
- Анализирует незавершенный код (больше ложных срабатываний)

**Настройка:**
```json
{
  "sentinelx.analyzeOnType": true,
  "sentinelx.debounceTime": 1000
}
```

### Режим 3: Только ручной анализ

**Когда использовать:**
- Для анализа по требованию
- При работе с очень большими файлами
- Для batch-анализа проекта

**Настройка:**
```json
{
  "sentinelx.analyzeOnSave": false,
  "sentinelx.analyzeOnType": false
}
```

## Установка для постоянного использования

После тестирования установите расширение:

```bash
cd /Users/gen/Desktop/Projects/SentinelX/V-1.0/vscode-extension
npm run package
code --install-extension sentinelx-1.0.0.vsix
```

Расширение будет доступно во всех проектах VS Code.

## Примеры найденных уязвимостей

### Buffer Overflow
```c
char buf[10];
strcpy(buf, input);  // 🔴 [CRITICAL][HIGH]
```

### Format String Vulnerability
```c
printf(user_input);  // 🔴 [CRITICAL][CERTAIN]
```

### Integer Overflow
```c
int size = count * 1024;  // 🟡 [WARNING][MEDIUM]
```

### Unbounded scanf
```c
char name[50];
scanf("%s", name);  // 🔴 [HIGH][MEDIUM]
```

## Integration с CI/CD

### GitHub Actions

```yaml
name: Security Check
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run SentinelX
        run: |
          ./build/SentinelX --source ./src --json --min-confidence HIGH
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

SentinelX --source . --min-confidence HIGH --json > /tmp/sentinelx.json

if [ $? -ne 0 ]; then
    echo "❌ Security vulnerabilities found!"
    cat /tmp/sentinelx.json
    exit 1
fi

echo "✅ Security check passed"
```

## Отладка и логи

### Output панель

Просмотр детальных логов анализа:

1. Откройте: **View → Output**
2. Выберите "SentinelX" из выпадающего списка
3. Смотрите логи в реальном времени

Пример вывода:
```
[12:34:56] Analyzing test.c...
[12:34:57] Analysis complete: 3 issue(s) found
```

### Extension Development Console

При разработке расширения:

1. Откройте **Help → Toggle Developer Tools**
2. Во вкладке Console смотрите внутренние логи расширения

## Troubleshooting

### "SentinelX executable not found"

**Причина:** VS Code не может найти исполняемый файл SentinelX

**Решение:**
1. Убедитесь, что SentinelX собран: `ls -la build/SentinelX`
2. Укажите полный путь в настройках:
   ```json
   {
     "sentinelx.executablePath": "/Users/gen/Desktop/Projects/SentinelX/V-1.0/build/SentinelX"
   }
   ```

### Нет подчеркиваний в коде

**Причина:** Анализ не запущен или есть ошибка

**Решение:**
1. Откройте **Output → SentinelX** и проверьте логи
2. Убедитесь, что файл имеет язык C/C++ (смотрите в правом нижнем углу)
3. Попробуйте ручной анализ: **Cmd+Shift+P** → "SentinelX: Analyze Current File"
4. Проверьте настройку `sentinelx.enabled` (должна быть `true`)

### Медленная работа

**Причина:** Анализ при наборе замедляет редактор

**Решение:**
```json
{
  "sentinelx.analyzeOnType": false,  // Отключить анализ при наборе
  "sentinelx.minConfidence": "HIGH",  // Повысить порог confidence
  "sentinelx.debounceTime": 2000      // Увеличить задержку до 2 секунд
}
```

### Слишком много ложных срабатываний

**Причина:** Низкий порог confidence

**Решение:**
```json
{
  "sentinelx.minConfidence": "HIGH",      // Только высокодостоверные
  "sentinelx.showInfoSeverity": false     // Скрыть INFO
}
```

## Архитектура расширения

```
┌─────────────────────────────────────────┐
│         VS Code Extension               │
│  ┌───────────────────────────────────┐  │
│  │   Extension.ts (Main Logic)       │  │
│  │                                   │  │
│  │  • Event Listeners               │  │
│  │    - onDidSaveTextDocument       │  │
│  │    - onDidChangeTextDocument     │  │
│  │                                   │  │
│  │  • Commands                      │  │
│  │    - analyzeCurrentFile          │  │
│  │    - analyzeWorkspace            │  │
│  │    - clearDiagnostics            │  │
│  │                                   │  │
│  │  • Diagnostics Collection        │  │
│  │    - Parse JSON output           │  │
│  │    - Create Diagnostic objects   │  │
│  │    - Update UI                   │  │
│  └───────────────────────────────────┘  │
│                   ↓                      │
│         exec("SentinelX --json")         │
│                   ↓                      │
│  ┌───────────────────────────────────┐  │
│  │       SentinelX Analyzer          │  │
│  │    (Native C++ Application)       │  │
│  └───────────────────────────────────┘  │
│                   ↓                      │
│            JSON Report                   │
│  {                                      │
│    "findings": [                        │
│      {                                  │
│        "file": "test.c",                │
│        "line": 5,                       │
│        "severity": "CRITICAL",          │
│        "message": "Buffer overflow"     │
│      }                                  │
│    ]                                    │
│  }                                      │
│                   ↓                      │
│  ┌───────────────────────────────────┐  │
│  │      VS Code Diagnostics API      │  │
│  │                                   │  │
│  │  • Underline code (squiggles)    │  │
│  │  • Problems panel entries        │  │
│  │  • Hover tooltips                │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## Дополнительные ресурсы

- 📖 **README.md** - Полная документация расширения
- 🚀 **QUICKSTART.md** - Быстрый старт за 5 минут
- 🔧 **INSTALLATION.md** - Детальная инструкция по установке
- 📝 **CHANGELOG.md** - История изменений

## Следующие шаги

1. ✅ **Установите зависимости**: `npm install`
2. ✅ **Скомпилируйте**: `npm run compile`
3. ✅ **Запустите**: Откройте в VS Code и нажмите F5
4. ✅ **Протестируйте**: Создайте файл с уязвимостью
5. ✅ **Установите**: `npm run package && code --install-extension *.vsix`

## Поддержка

Вопросы и баги: https://github.com/yourusername/sentinelx/issues

---

**Создано:** 16 декабря 2024
**Версия:** 1.0.0
**Автор:** SentinelX Team
