# SentinelX V-1.5 - New Architecture Quickstart

## 🎯 Что реализовано (Phase 1 - 85% Complete)

### ✅ Основные компоненты

1. **Modular Detector Framework**
   - `IDetector` - единый интерфейс для всех детекторов
   - `DetectorMetadata` - описание возможностей детектора
   - `AnalysisContext` - контекст с доступом ко всей инфраструктуре

2. **CWE Database Integration**
   - SQLite база данных с CWE информацией
   - Автоматический маппинг vulnerability ID → CWE
   - Enrichment findings с CWE data
   - Mitigations, relationships, examples

3. **AnalysisOrchestrator**
   - Координация всех детекторов
   - CWE enrichment pipeline
   - Progress reporting
   - Filtering на основе confidence и reachability

4. **Build System**
   - CMake с модульными опциями
   - SQLite3 интеграция
   - Поддержка будущих модулей (Plugins, DSL, AI)

## 📁 Структура

```
include/sentinelx/
├── core/
│   ├── types.h              # Расширенные типы (Finding с CWE/AI)
│   ├── analysis_context.h   # Контекст для детекторов
│   └── orchestrator.h       # Главный координатор
├── detectors/
│   ├── detector_interface.h # IDetector base interface
│   └── detector_metadata.h  # Metadata структура
└── cwe/
    └── cwe_repository.h     # CWE database API

src/
├── core/
│   └── orchestrator.cpp     # Orchestrator implementation
└── cwe/
    ├── cwe_schema.sql       # Database schema
    └── cwe_repository.cpp   # Repository implementation
```

## 🔨 Сборка

```bash
# Configure
cmake -B build -DSENTINELX_ENABLE_CWE=ON

# Build
cmake --build build

# Run
./build/SentinelX <файл>
```

### Опции сборки

```cmake
-DSENTINELX_USE_LIEF=ON       # LIEF binary analysis (default: ON)
-DSENTINELX_ENABLE_CWE=ON     # CWE database (default: ON)
-DSENTINELX_ENABLE_PLUGINS=OFF # Plugin system (Phase 3)
-DSENTINELX_ENABLE_DSL=OFF     # DSL rules (Phase 4)
-DSENTINELX_ENABLE_AI=OFF      # AI integration (Phase 5)
```

## 💡 Как создать детектор

### Пример: Simple Buffer Overflow Detector

```cpp
#include <sentinelx/detectors/detector_interface.h>
#include <sentinelx/core/types.h>

using namespace sentinelx;

class SimpleBufferDetector : public detectors::IDetector {
public:
    Findings analyze(const AnalysisContext& context) override {
        Findings findings;

        if (!context.has_source()) {
            return findings;  // Нужен source code
        }

        std::string code = context.source_code.value();

        // Простой поиск gets()
        if (code.find("gets(") != std::string::npos) {
            Finding f;
            f.kind = FindingKind::Source;
            f.severity = Severity::Critical;
            f.confidence = Confidence::Certain;
            f.id = "SIMPLE_GETS_DETECTED";
            f.message = "Dangerous gets() function detected";
            f.recommendation = "Use fgets() instead";

            // CWE будет добавлен автоматически через mapping
            f.source_location.file = context.file_path.value();

            findings.push_back(f);
        }

        return findings;
    }

    DetectorMetadata get_metadata() const override {
        DetectorMetadata meta;
        meta.name = "SimpleBufferDetector";
        meta.version = "1.0.0";
        meta.author = "Your Name";
        meta.description = "Detects gets() calls";
        meta.supported_languages = {"C", "C++"};
        meta.requires_source = true;
        meta.supported_cwes = {"CWE-120"};
        return meta;
    }

    std::vector<std::string> get_supported_cwes() const override {
        return {"CWE-120"};
    }
};
```

### Использование детектора

```cpp
#include <sentinelx/core/orchestrator.h>

int main() {
    // Конфигурация
    AnalyzerConfig config;
    config.cwe_database_path = "data/cwe/cwe_database.db";
    config.enrich_with_cwe = true;

    // Создать orchestrator
    AnalysisOrchestrator orchestrator(config);

    // Зарегистрировать детектор
    orchestrator.register_detector(
        std::make_unique<SimpleBufferDetector>()
    );

    // Анализ
    std::vector<std::string> sources = {"test.c"};
    Findings findings = orchestrator.analyze(sources, {});

    // Findings автоматически обогащены CWE info
    for (const auto& f : findings) {
        std::cout << f.id << ": " << f.message << "\n";
        if (f.cwe_id) {
            std::cout << "  CWE: " << f.cwe_id.value() << "\n";
        }
        if (f.cwe_name) {
            std::cout << "  Name: " << f.cwe_name.value() << "\n";
        }
    }
}
```

## 🗄️ CWE Database

### Инициализация

```cpp
#include <sentinelx/cwe/cwe_repository.h>

// Открыть/создать database
CweRepository repo("data/cwe/cwe_database.db");

// Инициализировать схему (только первый раз)
if (repo.get_cwe_count() == 0) {
    repo.initialize_database("src/cwe/cwe_schema.sql");
}
```

### Использование

```cpp
// Получить CWE info
auto cwe = repo.get_cwe_info("CWE-120");
if (cwe) {
    std::cout << cwe->name << "\n";
    std::cout << cwe->description << "\n";
}

// Получить mitigations
auto mits = repo.get_mitigations("CWE-120");
for (const auto& m : mits) {
    std::cout << m.phase << ": " << m.description << "\n";
}

// Map vulnerability ID → CWE
auto cwe_id = repo.map_vuln_to_cwe("SRC_UNSAFE_CALL_gets");
// Returns: "CWE-120"

// Добавить custom mapping
repo.add_vuln_mapping("MY_CUSTOM_VULN", "CWE-120", 95);
```

### Встроенные маппинги

```
SRC_UNSAFE_CALL_gets       → CWE-120 (Buffer Overflow)
SRC_UNSAFE_CALL_strcpy     → CWE-120
SRC_FORMAT_STRING_VULN     → CWE-134 (Format String)
SRC_COMMAND_INJECTION      → CWE-78  (Command Injection)
SRC_INTEGER_OVERFLOW_atoi  → CWE-190 (Integer Overflow)
SRC_ARITHMETIC_OVERFLOW    → CWE-190
... и другие
```

## 🔄 AnalysisOrchestrator API

```cpp
class AnalysisOrchestrator {
public:
    // Конструктор
    explicit AnalysisOrchestrator(const AnalyzerConfig& config);

    // Регистрация детекторов
    void register_detector(std::unique_ptr<IDetector> detector);

    // Загрузка плагинов (Phase 3)
    int load_plugins(const std::string& plugin_dir);

    // Загрузка DSL правил (Phase 4)
    int load_dsl_rules(const std::string& rules_dir);

    // Основной анализ
    Findings analyze(
        const std::vector<std::string>& source_paths,
        const std::vector<std::string>& binary_paths
    );

    // Progress callback
    void set_progress_callback(
        std::function<void(int current, int total, const std::string&)> callback
    );

    // Получить список детекторов
    std::vector<DetectorMetadata> get_registered_detectors() const;
};
```

## 📊 Enhanced Finding Structure

```cpp
struct Finding {
    // Core
    FindingKind kind;
    Severity severity;
    Confidence confidence;
    std::string id;
    std::string message;
    std::string recommendation;

    // Locations
    SourceLocation source_location;
    BinaryLocation binary_location;

    // Reachability
    bool is_in_reachable_function;

    // CWE Integration (NEW)
    std::optional<std::string> cwe_id;     // "CWE-120"
    std::optional<std::string> cwe_name;   // "Buffer Copy without..."

    // AI Integration (NEW - Phase 5)
    std::optional<std::string> ai_explanation;
    std::optional<std::string> ai_exploit_hints;
    float ai_confidence_adjustment;

    // Detector Metadata (NEW)
    std::string detector_name;
    std::string detector_version;
};
```

## 🚀 Next Steps (Phase 1 Completion)

1. **Create Example Detector**
   - Рефакторить BufferOverflowDetector из detectors.cpp
   - Показать полный пример использования IDetector
   - Демонстрация CWE enrichment

2. **Unit Tests**
   - Тесты для CweRepository
   - Тесты для AnalysisOrchestrator
   - Integration tests

## 🎓 Migration from Old API

### Старый способ (detectors.cpp):
```cpp
// Монолитный detectors.cpp (2,556 строк)
// Hardcoded vulnerability checks
// No CWE integration
```

### Новый способ:
```cpp
// Модульные детекторы
class MyDetector : public IDetector {
    Findings analyze(const AnalysisContext& ctx) override;
    DetectorMetadata get_metadata() const override;
};

// Автоматический CWE enrichment
orchestrator.register_detector(std::make_unique<MyDetector>());
auto findings = orchestrator.analyze(sources, binaries);
// findings[i].cwe_id автоматически заполнен!
```

## 📚 Документация

- `ARCHITECTURE_PROGRESS.md` - Детальный прогресс Phase 1
- `/Users/gen/.claude/plans/lucky-beaming-sundae.md` - Полный архитектурный план
- `src/cwe/cwe_schema.sql` - Схема CWE database
- `include/sentinelx/` - API headers с комментариями

## 🐛 Known Limitations (Phase 1)

- ⏳ Plugin loading не реализован (Phase 3)
- ⏳ DSL rule engine не реализован (Phase 4)
- ⏳ AI integration не реализован (Phase 5)
- ⏳ Параллельное выполнение детекторов (Phase 2)
- ⏳ Existing detectors не рефакторены (Phase 2)

## ✅ Что работает сейчас

- ✅ Сборка проекта
- ✅ CWE database с SQLite3
- ✅ AnalysisOrchestrator координация
- ✅ IDetector interface для новых детекторов
- ✅ CWE enrichment pipeline
- ✅ Filtering и configuration
- ✅ Backward compatibility с legacy API

---

**Статус**: Phase 1 - 85% Complete ✅
**Next**: Example Detector + Unit Tests
**Build Status**: ✅ Compiles Successfully
**CWE Database**: ✅ 9 CWEs + 14 Mappings
