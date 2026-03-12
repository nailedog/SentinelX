cmake_minimum_required(VERSION 3.15)

project(SentinelX LANGUAGES CXX)

# Build options
option(SENTINELX_USE_LIEF "Enable LIEF-based binary analysis" ON)
option(SENTINELX_ENABLE_CWE "Enable CWE database integration" ON)
option(SENTINELX_ENABLE_PLUGINS "Enable plugin system" OFF)  # Disabled by default for Phase 1
option(SENTINELX_ENABLE_DSL "Enable DSL rule engine" OFF)    # Disabled by default for Phase 1
option(SENTINELX_ENABLE_AI "Enable AI integration" OFF)      # Disabled by default for Phase 1

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(sentinelx_lib
    # Legacy components (will be refactored in Phase 2)
    src/analyzer.cpp
    src/disassembler.cpp
    src/detectors.cpp
    src/fsm.cpp
    src/utils.cpp
    src/binary_parser.cpp
    src/json_output.cpp
    src/call_site_analyzer.cpp
    src/stack_analyzer.cpp
    src/arithmetic_analyzer.cpp
    src/buffer_analysis.cpp
    src/taint_analysis.cpp
    src/call_graph.cpp

    # Exploit generation components
    src/shellcode_generator.cpp
    src/gadget_finder.cpp
    src/rop_builder.cpp
    src/exploit_templates.cpp
    src/exploit_engine.cpp

    # New modular architecture (Phase 1)
    src/core/orchestrator.cpp
    src/cwe/cwe_repository.cpp
    src/detectors/buffer_overflow_detector.cpp
)

target_include_directories(sentinelx_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(SENTINELX_USE_LIEF)
    message(STATUS "Using embedded LIEF")
    set(LIEF_LOGGING OFF CACHE BOOL "Disable LIEF logging")
    set(LIEF_EXAMPLES OFF CACHE BOOL "Disable LIEF examples")
    set(LIEF_TESTS OFF    CACHE BOOL "Disable LIEF tests")
    set(LIEF_PYTHON_API OFF CACHE BOOL "Disable Python API")

    add_subdirectory(LIEF)

    target_link_libraries(sentinelx_lib PUBLIC LIEF::LIEF)
    target_compile_definitions(sentinelx_lib PUBLIC SENTINELX_USE_LIEF)
endif()

# CWE Database Integration (SQLite3)
if(SENTINELX_ENABLE_CWE)
    message(STATUS "Enabling CWE database integration")

    # Find SQLite3
    find_package(SQLite3)
    if(SQLite3_FOUND)
        message(STATUS "Found SQLite3: ${SQLite3_VERSION}")
        target_link_libraries(sentinelx_lib PUBLIC SQLite::SQLite3)
    else()
        message(STATUS "SQLite3 not found via find_package, attempting pkg-config")
        find_package(PkgConfig)
        if(PkgConfig_FOUND)
            pkg_check_modules(SQLITE3 sqlite3)
            if(SQLITE3_FOUND)
                target_include_directories(sentinelx_lib PUBLIC ${SQLITE3_INCLUDE_DIRS})
                target_link_libraries(sentinelx_lib PUBLIC ${SQLITE3_LIBRARIES})
            else()
                message(WARNING "SQLite3 not found. CWE database will not be available.")
            endif()
        else()
            # Try direct linking (common on many systems)
            message(STATUS "Attempting direct SQLite3 linking")
            target_link_libraries(sentinelx_lib PUBLIC sqlite3)
        endif()
    endif()

    target_compile_definitions(sentinelx_lib PUBLIC SENTINELX_ENABLE_CWE)
endif()

# Plugin System (dynamic loading)
if(SENTINELX_ENABLE_PLUGINS)
    message(STATUS "Enabling plugin system")
    target_compile_definitions(sentinelx_lib PUBLIC SENTINELX_ENABLE_PLUGINS)

    # Add plugin loader sources when implemented
    # target_sources(sentinelx_lib PRIVATE src/plugin/plugin_loader.cpp)

    # Link with dl on Unix systems
    if(UNIX AND NOT APPLE)
        target_link_libraries(sentinelx_lib PUBLIC ${CMAKE_DL_LIBS})
    endif()
endif()

# DSL Rule Engine
if(SENTINELX_ENABLE_DSL)
    message(STATUS "Enabling DSL rule engine")
    target_compile_definitions(sentinelx_lib PUBLIC SENTINELX_ENABLE_DSL)

    # Add DSL sources when implemented
    # target_sources(sentinelx_lib PRIVATE
    #     src/dsl/lexer.cpp
    #     src/dsl/parser.cpp
    #     src/dsl/compiler.cpp
    # )
endif()

# AI Integration
if(SENTINELX_ENABLE_AI)
    message(STATUS "Enabling AI integration")
    target_compile_definitions(sentinelx_lib PUBLIC SENTINELX_ENABLE_AI)

    # Add AI sources when implemented
    # target_sources(sentinelx_lib PRIVATE
    #     src/ai/model_manager.cpp
    #     src/ai/local_inference.cpp
    # )
endif()

add_executable(SentinelX src/main.cpp)
target_link_libraries(SentinelX PRIVATE sentinelx_lib)

# Example/Demo executable (new architecture)
option(SENTINELX_BUILD_EXAMPLES "Build example programs" ON)
if(SENTINELX_BUILD_EXAMPLES)
    add_executable(demo_new_architecture examples/demo_new_architecture.cpp)
    target_link_libraries(demo_new_architecture PRIVATE sentinelx_lib)
    message(STATUS "Building example: demo_new_architecture")
endif()

if(MSVC)
    target_compile_options(sentinelx_lib PRIVATE /W4 /permissive-)
    target_compile_options(SentinelX PRIVATE /W4 /permissive-)
else()
    target_compile_options(sentinelx_lib PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(SentinelX PRIVATE -Wall -Wextra -Wpedantic)
endif()
