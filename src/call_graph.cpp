#include "call_graph.h"
#include "utils.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <iostream>

namespace sentinel {

void CallGraphAnalyzer::add_call(const std::string& caller, const std::string& callee) {
    call_graph_[caller].push_back(callee);
    needs_recompute_ = true;
}

void CallGraphAnalyzer::add_entry_point(const std::string& function_name) {
    entry_points_.insert(function_name);
    needs_recompute_ = true;
}

void CallGraphAnalyzer::clear() {
    call_graph_.clear();
    entry_points_.clear();
    reachable_functions_.clear();
    needs_recompute_ = true;
}

void CallGraphAnalyzer::compute_reachable_functions() const {
    if (!needs_recompute_) {
        return;
    }

    reachable_functions_.clear();

    for (const auto& entry : entry_points_) {
        dfs(entry, reachable_functions_);
    }

    for (const auto& entry : entry_points_) {
        reachable_functions_.insert(entry);
    }

    needs_recompute_ = false;
}

void CallGraphAnalyzer::dfs(const std::string& func, std::unordered_set<std::string>& visited) const {
    if (visited.find(func) != visited.end()) {
        return; 
    }

    visited.insert(func);

    auto it = call_graph_.find(func);
    if (it != call_graph_.end()) {
        for (const auto& callee : it->second) {
            dfs(callee, visited);
        }
    }
}

bool CallGraphAnalyzer::is_reachable(const std::string& function_name) const {
    compute_reachable_functions();
    return reachable_functions_.find(function_name) != reachable_functions_.end();
}

std::unordered_set<std::string> CallGraphAnalyzer::get_reachable_functions() const {
    compute_reachable_functions();
    return reachable_functions_;
}

void CallGraphAnalyzer::analyze_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    std::regex func_def_pattern(R"(\b([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{)");

    std::regex func_decl_pattern(R"(\b([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*$)");

    std::regex func_call_pattern(R"(\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\()");

    std::string current_function;
    std::string pending_function; 
    std::smatch match;

    std::istringstream content_stream(content);
    std::string line;
    int brace_depth = 0;

    while (std::getline(content_stream, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#' ||
            trimmed.substr(0, 2) == "//" || trimmed.substr(0, 2) == "/*") {
            continue;
        }

        if (std::regex_search(line, match, func_def_pattern)) {
            current_function = match[2].str();
            pending_function.clear();
            brace_depth = 1;

            if (current_function == "main") {
                add_entry_point("main");
            }
            continue;
        }

        if (brace_depth == 0 && std::regex_search(line, match, func_decl_pattern)) {
            pending_function = match[2].str();
            continue;
        }

        if (!pending_function.empty() && trimmed.find('{') != std::string::npos) {
            current_function = pending_function;
            pending_function.clear();
            brace_depth = 1;

            if (current_function == "main") {
                add_entry_point("main");
            }
            continue;
        }

        for (char c : line) {
            if (c == '{') brace_depth++;
            else if (c == '}') brace_depth--;

            if (brace_depth == 0) {
                current_function.clear();
                break;
            }
        }

        if (!current_function.empty() && brace_depth > 0) {
            std::string::const_iterator searchStart(line.cbegin());
            while (std::regex_search(searchStart, line.cend(), match, func_call_pattern)) {
                std::string called_func = match[1].str();

                if (called_func != "if" && called_func != "while" &&
                    called_func != "for" && called_func != "switch" &&
                    called_func != "return" && called_func != "sizeof") {
                    add_call(current_function, called_func);
                }

                searchStart = match.suffix().first;
            }
        }
    }

    if (entry_points_.empty()) {
        for (const auto& pair : call_graph_) {
            add_entry_point(pair.first);
        }
    }
}

}
