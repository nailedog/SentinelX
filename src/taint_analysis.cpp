#include "taint_analysis.h"
#include <regex>

namespace sentinel {

void TaintAnalyzer::mark_tainted(const std::string& var, TaintSource source) {
    taint_map_[var] = source;
}

bool TaintAnalyzer::is_tainted(const std::string& var) const {
    auto it = taint_map_.find(var);
    if (it != taint_map_.end()) {
        return is_dangerous_source(it->second);
    }
    return false; 
}

TaintSource TaintAnalyzer::get_source(const std::string& var) const {
    auto it = taint_map_.find(var);
    if (it != taint_map_.end()) {
        return it->second;
    }
    return TaintSource::UNKNOWN;
}

void TaintAnalyzer::propagate_taint(const std::string& dst, const std::string& src) {
    auto source = get_source(src);
    if (source != TaintSource::UNKNOWN) {
        mark_tainted(dst, source);
    }
}

void TaintAnalyzer::analyze_code(const std::string& code) {
    analyze_user_input_sources(code);
    analyze_constant_sources(code);
    analyze_constant_arrays(code);
    analyze_function_parameters(code);
    analyze_assignments(code);
}

void TaintAnalyzer::analyze_user_input_sources(const std::string& code) {
    std::regex scanf_re(R"(scanf\s*\(\s*[^,]+,\s*&?\s*(\w+)\s*\))");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), scanf_re);
         it != std::sregex_iterator(); ++it) {
        mark_tainted((*it)[1].str(), TaintSource::USER_INPUT);
    }

    std::regex gets_re(R"(gets\s*\(\s*(\w+)\s*\))");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), gets_re);
         it != std::sregex_iterator(); ++it) {
        mark_tainted((*it)[1].str(), TaintSource::USER_INPUT);
    }

    std::regex fgets_re(R"(fgets\s*\(\s*(\w+)\s*,)");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), fgets_re);
         it != std::sregex_iterator(); ++it) {
        mark_tainted((*it)[1].str(), TaintSource::USER_INPUT);
    }

    std::regex argv_re(R"((\w+)\s*=\s*argv\s*\[)");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), argv_re);
         it != std::sregex_iterator(); ++it) {
        mark_tainted((*it)[1].str(), TaintSource::USER_INPUT);
    }

    std::regex getenv_re(R"((\w+)\s*=\s*getenv\s*\()");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), getenv_re);
         it != std::sregex_iterator(); ++it) {
        mark_tainted((*it)[1].str(), TaintSource::USER_INPUT);
    }

    std::regex read_re(R"(read\s*\(\s*\w+\s*,\s*(\w+)\s*,)");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), read_re);
         it != std::sregex_iterator(); ++it) {
        mark_tainted((*it)[1].str(), TaintSource::FILE_INPUT);
    }

    std::regex recv_re(R"(recv(?:from)?\s*\(\s*\w+\s*,\s*(\w+)\s*,)");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), recv_re);
         it != std::sregex_iterator(); ++it) {
        mark_tainted((*it)[1].str(), TaintSource::NETWORK);
    }
}

void TaintAnalyzer::analyze_constant_sources(const std::string& code) {
    std::regex const_str_re(R"((\w+)\s*=\s*"[^"]*")");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), const_str_re);
         it != std::sregex_iterator(); ++it) {
        mark_tainted((*it)[1].str(), TaintSource::CONSTANT);
    }

    std::regex char_init_re(R"(\bchar\s+(\w+)\s*\[\s*\d*\s*\]\s*=\s*"[^"]*")");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), char_init_re);
         it != std::sregex_iterator(); ++it) {
        mark_tainted((*it)[1].str(), TaintSource::CONSTANT);
    }

    std::regex char_brace_init_re(R"(\bchar\s+(\w+)\s*\[\s*\d*\s*\]\s*=\s*\{)");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), char_brace_init_re);
         it != std::sregex_iterator(); ++it) {
        // Assume brace initialization is constant for simplicity
        mark_tainted((*it)[1].str(), TaintSource::CONSTANT);
    }
    
    std::regex const_num_re(R"((\w+)\s*=\s*\d+)");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), const_num_re);
         it != std::sregex_iterator(); ++it) {
        std::string var = (*it)[1].str();
        if (get_source(var) == TaintSource::UNKNOWN) {
            mark_tainted(var, TaintSource::CONSTANT);
        }
    }
}

void TaintAnalyzer::analyze_assignments(const std::string& code) {
    std::regex assign_re(R"((\w+)\s*=\s*(\w+)(?:\s|;|$))");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), assign_re);
         it != std::sregex_iterator(); ++it) {
        std::string dst = (*it)[1].str();
        std::string src = (*it)[2].str();

        propagate_taint(dst, src);
    }
}

void TaintAnalyzer::analyze_constant_arrays(const std::string& code) {
    std::regex const_array_re(R"((?:const\s+)?char\s*\*\s*(\w+)\s*\[\s*\]\s*=\s*\{)");

    for (auto it = std::sregex_iterator(code.begin(), code.end(), const_array_re);
         it != std::sregex_iterator(); ++it) {
        std::string array_name = (*it)[1].str();

        size_t start_pos = it->position();
        size_t brace_pos = code.find('{', start_pos);
        if (brace_pos == std::string::npos) continue;

        size_t end_pos = code.find('}', brace_pos);
        if (end_pos == std::string::npos) continue;

        std::string init_list = code.substr(brace_pos + 1, end_pos - brace_pos - 1);

        bool all_constants = true;
        size_t pos = 0;
        while (pos < init_list.length()) {
            while (pos < init_list.length() &&
                   (std::isspace(static_cast<unsigned char>(init_list[pos])) || init_list[pos] == ',')) {
                pos++;
            }
            if (pos >= init_list.length()) break;

            if (init_list[pos] != '"') {
                all_constants = false;
                break;
            }

            pos++;
            while (pos < init_list.length() && init_list[pos] != '"') {
                if (init_list[pos] == '\\') pos++;
                pos++;
            }
            if (pos < init_list.length()) pos++; 
        }

        if (all_constants) {
            constant_arrays_.insert(array_name);
        }
    }
}

void TaintAnalyzer::analyze_function_parameters(const std::string& code) {
    std::regex func_param_re(
        R"((?:void|int|char|bool|long|short|unsigned|signed|size_t|std::string)\s+\w+\s*\([^)]*\bchar\s*\*\s*(\w+)|(?:void|int|char|bool|long|short|unsigned|signed|size_t|std::string)\s+\w+\s*\([^)]*\bchar\s+(\w+)\s*\[)");

    for (auto it = std::sregex_iterator(code.begin(), code.end(), func_param_re);
         it != std::sregex_iterator(); ++it) {
        std::string param_name;
        if ((*it)[1].matched) {
            param_name = (*it)[1].str();
        } else if ((*it)[2].matched) {
            param_name = (*it)[2].str();
        }

        if (!param_name.empty()) {
            mark_tainted(param_name, TaintSource::UNKNOWN);
        }
    }
}

void TaintAnalyzer::clear() {
    taint_map_.clear();
    constant_arrays_.clear();
}

bool TaintAnalyzer::is_dangerous_source(TaintSource source) {
    switch (source) {
        case TaintSource::USER_INPUT:
        case TaintSource::FILE_INPUT:
        case TaintSource::NETWORK:
        case TaintSource::UNKNOWN:
            return true;

        case TaintSource::CONSTANT:
        case TaintSource::SANITIZED:
            return false;
    }
    return true;  
}

bool TaintAnalyzer::is_expression_tainted(const std::string& expr) const {
    TaintSource source = get_expression_source(expr);
    return is_dangerous_source(source);
}

TaintSource TaintAnalyzer::get_expression_source(const std::string& expr) const {
    std::string trimmed = expr;
    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.front()))) {
        trimmed.erase(0, 1);
    }
    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.back()))) {
        trimmed.pop_back();
    }

    size_t bracket_pos = trimmed.find('[');
    if (bracket_pos != std::string::npos && bracket_pos > 0) {
        std::string array_name = trimmed.substr(0, bracket_pos);
        while (!array_name.empty() && std::isspace(static_cast<unsigned char>(array_name.back()))) {
            array_name.pop_back();
        }

        if (constant_arrays_.find(array_name) != constant_arrays_.end()) {
            return TaintSource::CONSTANT;
        }

        if (array_name == "argv") {
            return TaintSource::USER_INPUT;
        }
    }

    if (trimmed.find("argv[") == 0 || trimmed.find("argv [") == 0) {
        return TaintSource::USER_INPUT;
    }

    if (trimmed.find("getenv") != std::string::npos &&
        trimmed.find("(") != std::string::npos) {
        return TaintSource::USER_INPUT;
    }

    if (trimmed.find("gets") != std::string::npos &&
        trimmed.find("(") != std::string::npos) {
        return TaintSource::USER_INPUT;
    }

    if (trimmed.find("recv") == 0 && trimmed.find("(") != std::string::npos) {
        return TaintSource::NETWORK;
    }

    if (trimmed.find("read") == 0 && trimmed.find("(") != std::string::npos) {
        return TaintSource::FILE_INPUT;
    }

    if (trimmed.find("fgets") != std::string::npos &&
        trimmed.find("(") != std::string::npos) {
        return TaintSource::FILE_INPUT;
    }

    if (!trimmed.empty() && trimmed.front() == '"' && trimmed.back() == '"') {
        return TaintSource::CONSTANT;
    }

    bool is_number = !trimmed.empty() && std::isdigit(static_cast<unsigned char>(trimmed[0]));
    if (is_number) {
        for (char c : trimmed) {
            if (!std::isdigit(static_cast<unsigned char>(c)) && c != '.') {
                is_number = false;
                break;
            }
        }
        if (is_number) {
            return TaintSource::CONSTANT;
        }
    }

    auto source = get_source(trimmed);
    if (source != TaintSource::UNKNOWN) {
        return source;
    }

    return TaintSource::UNKNOWN;
}

} // namespace sentinel
