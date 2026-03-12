#include "detectors.h"

#include "binary_parser.h"
#include "disassembler.h"
#include "call_site_analyzer.h"
#include "fsm.hpp"
#include "utils.h"
#include "buffer_analysis.h"
#include "taint_analysis.h"

#include <filesystem>
#include <fstream>
#include <regex>
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <functional>
#include <set>
#include <optional>
#include <limits>

namespace fs = std::filesystem;

namespace sentinel {

namespace {

    bool is_format_arg_likely_literal(const std::vector<Instruction>& context_insts,
                                   std::uint64_t call_addr,
                                   const std::string& arch,
                                   int arg_position = 0) {
    auto call_it = std::find_if(context_insts.begin(), context_insts.end(),
                                [call_addr](const Instruction& i) {
                                    return i.address == call_addr;
                                });

    if (call_it == context_insts.begin()) {
        return false;
    }

    std::string target_reg;

    if (arch == "arm64" || arch == "arm") {
        target_reg = "x" + std::to_string(arg_position);
    } else if (arch == "x86_64") {
        const char* regs[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
        if (arg_position >= 0 && arg_position < 6) {
            target_reg = regs[arg_position];
        } else {
            return false;
        }
    } else if (arch == "x86") {
        return false;
    } else {
        return false;
    }

    if (arch == "arm64" || arch == "arm") {
        for (auto it = call_it - 1; it != context_insts.begin() &&
             std::distance(it, call_it) <= 6; --it) {

            const auto& inst = *it;

            if (inst.mnemonic == "adrp" && inst.operands.find(target_reg) == 0) {
                return true; // Loading literal address
            }

            if (inst.mnemonic == "ldr" && inst.operands.find(target_reg) == 0) {
                // Check if loading from stack or register
                if (inst.operands.find("[sp") != std::string::npos ||
                    inst.operands.find("[x") != std::string::npos) {
                    return false; // Loading from variable
                }
            }
        }
    } else if (arch == "x86_64" || arch == "x86") {
        // Check for lea rdi, [rip + offset] or mov rdi, offset
        for (auto it = call_it - 1; it != context_insts.begin() &&
             std::distance(it, call_it) <= 4; --it) {

            const auto& inst = *it;

            if (inst.mnemonic == "lea" &&
                (inst.operands.find("rdi") != std::string::npos ||
                 inst.operands.find("edi") != std::string::npos)) {
                if (inst.operands.find("rip") != std::string::npos) {
                    return true; 
                }
            }

            if (inst.mnemonic == "mov" &&
                (inst.operands.find("rdi") != std::string::npos ||
                 inst.operands.find("edi") != std::string::npos)) {
                if (inst.operands.find("rsp") != std::string::npos ||
                    inst.operands.find("rbp") != std::string::npos) {
                    return false; 
                }
            }
        }
    }

    return false;
}

bool is_source_file(const fs::path& p) {
    const std::string ext = to_lower(p.extension().string());
    return ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx" ||
           ext == ".h" || ext == ".hpp" || ext == ".hh";
}

std::string strip_comments_preserve_strings(const std::string& line,
                                            bool& in_block_comment) {
    enum class State {
        Normal,
        InString,
        InChar,
        InLineComment,
        InBlockComment
    };

    State state = in_block_comment ? State::InBlockComment : State::Normal;
    std::string out;

    for (std::size_t i = 0; i < line.size(); ++i) {
        char c    = line[i];
        char next = (i + 1 < line.size()) ? line[i + 1] : '\0';

        switch (state) {
            case State::Normal:
                if (c == '/' && next == '/') {
                    state = State::InLineComment;
                    ++i;
                } else if (c == '/' && next == '*') {
                    state = State::InBlockComment;
                    in_block_comment = true;
                    ++i;
                } else if (c == '"') {
                    state = State::InString;
                    out.push_back(c);
                } else if (c == '\'') {
                    state = State::InChar;
                    out.push_back(c);
                } else {
                    out.push_back(c);
                }
                break;

            case State::InString:
                out.push_back(c);
                if (c == '\\' && next != '\0') {
                    out.push_back(next);
                    ++i;
                } else if (c == '"') {
                    state = State::Normal;
                }
                break;

            case State::InChar:
                out.push_back(c);
                if (c == '\\' && next != '\0') {
                    out.push_back(next);
                    ++i;
                } else if (c == '\'') {
                    state = State::Normal;
                }
                break;

            case State::InLineComment:
                break;

            case State::InBlockComment:
                if (c == '*' && next == '/') {
                    state = State::Normal;
                    in_block_comment = false;
                    ++i;
                }
                break;
        }
    }

    return out;
}

bool contains_function_call(const std::string& code,
                            const std::string& func_name,
                            std::size_t* first_pos = nullptr) {
    std::size_t pos = 0;
    while ((pos = code.find(func_name, pos)) != std::string::npos) {
        bool left_ok = (pos == 0) ||
            (!std::isalnum(static_cast<unsigned char>(code[pos - 1])) &&
             code[pos - 1] != '_');
        std::size_t end = pos + func_name.size();
        while (end < code.size() &&
               std::isspace(static_cast<unsigned char>(code[end]))) {
            ++end;
        }
        bool right_ok = (end < code.size() && code[end] == '(');
        if (left_ok && right_ok) {
            if (first_pos) {
                *first_pos = pos;
            }
            return true;
        }
        pos += func_name.size();
    }
    return false;
}

bool has_format_string_vulnerability(const std::string& code,
                                     std::size_t func_pos) {
    std::size_t paren = code.find('(', func_pos);
    if (paren == std::string::npos) return false;

    std::string func_name;
    for (std::size_t i = func_pos; i < paren; ++i) {
        if (std::isalnum(code[i]) || code[i] == '_') {
            func_name += code[i];
        }
    }

    bool check_second_arg = (func_name == "fprintf" || func_name == "vfprintf" ||
                             func_name == "dprintf");

    std::size_t arg_start = paren + 1;
    while (arg_start < code.size() &&
           std::isspace(static_cast<unsigned char>(code[arg_start]))) {
        ++arg_start;
    }

    if (arg_start >= code.size()) return false;

    std::string remaining = code.substr(arg_start);

    if (check_second_arg) {
        std::size_t comma = remaining.find(',');
        if (comma == std::string::npos) return false;

        std::size_t second_arg = comma + 1;
        while (second_arg < remaining.size() &&
               std::isspace(static_cast<unsigned char>(remaining[second_arg]))) {
            ++second_arg;
        }
        if (second_arg >= remaining.size()) return false;

        if (remaining[second_arg] == '"') {
            return false; // fprintf(file, "literal", ...) is safe
        }
        return true;
    }

    if (code[arg_start] == '"') {
        return false; // First arg is a string literal (safe)
    }

    return true;
}

bool scanf_format_has_unbounded_s(const std::string& code,
                                  std::size_t func_pos) {
    std::size_t paren = code.find('(', func_pos);
    if (paren == std::string::npos) return false;
    std::size_t first_quote = code.find('"', paren);
    if (first_quote == std::string::npos) return false;

    bool escape = false;
    for (std::size_t i = first_quote + 1; i < code.size(); ++i) {
        char c = code[i];
        if (!escape && c == '\\') {
            escape = true;
            continue;
        }
        if (!escape && c == '"') {
            break;
        }
        escape = false;

        if (c == 's' && i > first_quote && code[i - 1] == '%') {
            bool has_digit = false;
            std::size_t j = i - 1;
            while (j > first_quote && code[j] != '%') {
                if (std::isdigit(static_cast<unsigned char>(code[j]))) {
                    has_digit = true;
                    break;
                }
                --j;
            }
            if (!has_digit) {
                return true;
            }
        }
    }
    return false;
}

std::string get_source_context(const std::vector<std::string>& all_lines,
                               std::size_t target_line,
                               std::size_t context_before = 2,
                               std::size_t context_after = 2) {
    if (all_lines.empty() || target_line == 0 || target_line > all_lines.size()) {
        return "";
    }

    std::size_t idx = target_line - 1;

    std::size_t start = (idx >= context_before) ? (idx - context_before) : 0;
    std::size_t end = std::min(idx + context_after + 1, all_lines.size());

    std::ostringstream oss;
    for (std::size_t i = start; i < end; ++i) {
        std::size_t line_no = i + 1;
        oss << "    " << line_no;
        if (line_no == target_line) {
            oss << " > ";
        } else {
            oss << " | ";
        }
        oss << all_lines[i] << "\n";
    }

    return oss.str();
}

void add_source_finding(Findings& out,
                        const std::string& id,
                        Severity severity,
                        const std::string& msg,
                        const std::string& file,
                        std::size_t line,
                        const std::string& recommendation,
                        const std::string& context = "",
                        const std::string& function_name = "",
                        Confidence confidence = Confidence::Medium) {
    Finding f;
    f.kind  = FindingKind::Source;
    f.severity = severity;
    f.confidence = confidence;
    f.id    = id;
    f.message = msg;
    f.recommendation = recommendation;
    f.source_location.file = file;
    f.source_location.line = line;
    f.source_location.context = context;
    f.source_location.function_name = function_name;
    out.push_back(std::move(f));
}

std::string to_hex64(std::uint64_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

void add_binary_finding(Findings& out,
                        const std::string& id,
                        Severity severity,
                        const std::string& msg,
                        const std::string& arch,
                        const std::string& segment = {},
                        std::uint64_t offset = 0,
                        const std::string& recommendation = {},
                        const std::string& disasm = {},
                        const std::string& function_name = {},
                        std::uint64_t return_address = 0,
                        Confidence confidence = Confidence::Medium) {
    Finding f;
    f.kind = FindingKind::Binary;
    f.severity = severity;
    f.confidence = confidence;
    f.id = id;
    f.message = msg;
    f.recommendation = recommendation;
    f.binary_location.arch = arch;
    f.binary_location.segment_or_section = segment;
    f.binary_location.offset = offset;
    f.binary_location.disasm = disasm;
    f.binary_location.function_name = function_name;
    f.binary_location.return_address = return_address;
    out.push_back(std::move(f));
}

/*
Delete this segment, deterministic

std::vector<std::pair<std::size_t, std::string>> find_all_patterns(
    const std::string& text, 
    const std::vector<std::string>& patterns) {
    
    std::vector<std::pair<std::size_t, std::string>> results;
    
    for (const auto& pattern : patterns) {
        if (pattern.empty()) continue;
        
        auto it = text.begin();
        while (it != text.end()) {
            auto found = std::search(
                it, text.end(),
                pattern.begin(), pattern.end(),
                [](char a, char b) {
                    return std::tolower(static_cast<unsigned char>(a)) == 
                           std::tolower(static_cast<unsigned char>(b));
                }
            );
            
            if (found == text.end()) {
                break;
            }
            
            std::size_t pos = std::distance(text.begin(), found);
            results.emplace_back(pos, pattern);
            it = found + 1; 
        }
    }
    
    std::sort(results.begin(), results.end(), 
              [](const auto& a, const auto& b) { return a.first < b.first; });
    
    return results;
}
*/

static constexpr std::uint64_t kRKBase = 263ULL;
static constexpr std::uint64_t kRKMod  = 1000000007ULL;

std::uint64_t rk_compute_hash(const std::string& s, std::size_t m) {
    std::uint64_t h = 0;
    for (std::size_t i = 0; i < m; ++i) {
        h = (h * kRKBase + static_cast<unsigned char>(s[i])) % kRKMod;
    }
    return h;
}

std::uint64_t rk_compute_reverse_hash(const std::string& s,
                                      std::size_t pos,
                                      std::size_t m) {
    std::uint64_t h = 0;
    for (std::size_t i = 0; i < m; ++i) {
        unsigned char c = static_cast<unsigned char>(s[pos + m - 1 - i]);
        h = (h * kRKBase + c) % kRKMod;
    }
    return h;
}

std::uint64_t rk_rehash(std::uint64_t old_hash,
                        unsigned char old_ch,
                        unsigned char new_ch,
                        std::uint64_t highest_power) {
    std::uint64_t remove =
        (highest_power * static_cast<std::uint64_t>(old_ch)) % kRKMod;

    std::uint64_t without_first = (kRKMod + old_hash - remove) % kRKMod;
    std::uint64_t result =
        (without_first * kRKBase + static_cast<std::uint64_t>(new_ch)) % kRKMod;

    return result;
}

std::vector<std::size_t> rabin_karp_search_single(const std::string& text,
                                                  const std::string& pattern) {
    std::vector<std::size_t> matches;

    const std::size_t n = text.size();
    const std::size_t m = pattern.size();

    if (m == 0 || n < m) {
        return matches;
    }

    const std::uint64_t pattern_hash  = rk_compute_hash(pattern, m);
    const std::uint64_t pattern_rhash = rk_compute_reverse_hash(pattern, 0, m);

    // base^{m-1}
    std::uint64_t highest_power = 1;
    for (std::size_t i = 1; i < m; ++i) {
        highest_power = (highest_power * kRKBase) % kRKMod;
    }

    std::uint64_t window_hash = rk_compute_hash(text, m);

    for (std::size_t i = 0; i + m <= n; ++i) {
        if (window_hash == pattern_hash) {
            std::uint64_t rhash = rk_compute_reverse_hash(text, i, m);
            if (rhash == pattern_rhash &&
                text.compare(i, m, pattern) == 0) {
                matches.push_back(i);
            }
        }

        if (i + m < n) {
            window_hash = rk_rehash(
                window_hash,
                static_cast<unsigned char>(text[i]),
                static_cast<unsigned char>(text[i + m]),
                highest_power
            );
        }
    }

    return matches;
}

std::vector<std::pair<std::size_t, std::string>> rabin_karp_search(
    const std::string& text,
    const std::vector<std::string>& patterns) {

    std::vector<std::pair<std::size_t, std::string>> results;

    for (const auto& pattern : patterns) {
        if (pattern.empty() || pattern.size() > text.size()) {
            continue;
        }

        auto positions = rabin_karp_search_single(text, pattern);
        for (std::size_t pos : positions) {
            results.emplace_back(pos, pattern);
        }
    }

    std::sort(results.begin(), results.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    return results;
}

std::string extract_function_name(const std::string& code) {
    // Match function definitions like:
    // int main(...) {
    // void foo(int x) {
    // static inline void bar() {
    // etc.
    static const std::regex func_def_re(
        R"((?:^|[^\w])(?:static\s+)?(?:inline\s+)?(?:virtual\s+)?(?:const\s+)?(?:\w+\s+[\*&]*\s*)?(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:\{|$))"
    );

    std::smatch m;
    if (std::regex_search(code, m, func_def_re)) {
        std::string candidate = m[1].str();
        // Filter out common C++ keywords that might be matched
        static const std::vector<std::string> keywords = {
            "if", "while", "for", "switch", "return", "sizeof", "typedef"
        };
        if (std::find(keywords.begin(), keywords.end(), candidate) == keywords.end()) {
            return candidate;
        }
    }
    return "";
}

std::optional<int64_t> evaluate_constant_expression(const std::string& expr) {
    std::string trimmed_expr = trim(expr);

    // Remove L/LL suffixes
    std::string clean_expr = trimmed_expr;
    if (!clean_expr.empty()) {
        size_t pos = clean_expr.length() - 1;
        while (pos > 0 && (clean_expr[pos] == 'L' || clean_expr[pos] == 'l' ||
                           clean_expr[pos] == 'U' || clean_expr[pos] == 'u')) {
            pos--;
        }
        clean_expr = clean_expr.substr(0, pos + 1);
    }

    if (clean_expr.find("0x") == 0 || clean_expr.find("0X") == 0) {
        try {
            return std::stoll(clean_expr, nullptr, 16);
        } catch (...) {
            return std::nullopt;
        }
    }

    static const std::regex simple_num_re(R"(^-?\d+$)");
    if (std::regex_match(clean_expr, simple_num_re)) {
        try {
            return std::stoll(clean_expr);
        } catch (...) {
            return std::nullopt;
        }
    }

    static const std::regex shift_re(R"(\(?(\d+)[ULul]*\s*<<\s*(\d+)\)?)");
    std::smatch m;
    if (std::regex_match(clean_expr, m, shift_re)) {
        try {
            int64_t base = std::stoll(m[1].str());
            int64_t shift = std::stoll(m[2].str());
            if (shift < 0 || shift >= 63) {
                return std::nullopt;
            }
            return base << shift;
        } catch (...) {
            return std::nullopt;
        }
    }

    static const std::regex shift_minus_re(R"(\(?(\d+)[ULul]*\s*<<\s*(\d+)\s*-\s*(\d+)\)?)");
    if (std::regex_match(clean_expr, m, shift_minus_re)) {
        try {
            int64_t base = std::stoll(m[1].str());
            int64_t shift = std::stoll(m[2].str());
            int64_t subtract = std::stoll(m[3].str());
            if (shift < 0 || shift >= 63) {
                return std::nullopt;
            }
            return (base << shift) - subtract;
        } catch (...) {
            return std::nullopt;
        }
    }

    // Handle INT_MAX, INT_MIN, etc.
    if (clean_expr == "INT_MAX") return std::numeric_limits<int32_t>::max();
    if (clean_expr == "INT_MIN") return std::numeric_limits<int32_t>::min();
    if (clean_expr == "UINT_MAX") return std::numeric_limits<uint32_t>::max();
    if (clean_expr == "LONG_MAX") return std::numeric_limits<int64_t>::max();
    if (clean_expr == "LONG_MIN") return std::numeric_limits<int64_t>::min();
    if (clean_expr == "SIZE_MAX") return std::numeric_limits<size_t>::max();

    return std::nullopt;
}

bool would_multiply_overflow(int64_t a, int64_t b) {
    constexpr int64_t max_int32 = std::numeric_limits<int32_t>::max();
    constexpr int64_t min_int32 = std::numeric_limits<int32_t>::min();

    if (a == 0 || b == 0) return false;

    if (a > 0 && b > 0) {
        return a > max_int32 / b;
    } else if (a < 0 && b < 0) {
        return a < max_int32 / b;
    } else if (a > 0 && b < 0) {
        return b < min_int32 / a;
    } else { // a < 0 && b > 0
        return a < min_int32 / b;
    }
}

bool would_add_overflow(int64_t a, int64_t b) {
    constexpr int64_t max_int32 = std::numeric_limits<int32_t>::max();
    constexpr int64_t min_int32 = std::numeric_limits<int32_t>::min();

    if (b > 0 && a > max_int32 - b) return true;
    if (b < 0 && a < min_int32 - b) return true;
    return false;
}

bool would_subtract_overflow(int64_t a, int64_t b) {
    constexpr int64_t max_int32 = std::numeric_limits<int32_t>::max();
    constexpr int64_t min_int32 = std::numeric_limits<int32_t>::min();

    if (b < 0 && a > max_int32 + b) return true;
    if (b > 0 && a < min_int32 + b) return true;
    return false;
}

bool is_constant_expression(const std::string& expr1, const std::string& expr2) {
    static const std::regex num_re(R"(^\d+$)");

    bool both_simple_nums = std::regex_match(expr1, num_re) && std::regex_match(expr2, num_re);
    if (both_simple_nums) {
        return true;
    }

    auto val1 = evaluate_constant_expression(expr1);
    auto val2 = evaluate_constant_expression(expr2);

    return val1.has_value() && val2.has_value();
}

std::optional<std::string> find_variable_initialization(
    const std::vector<std::string>& lines,
    std::size_t current_line,
    const std::string& var_name) {

    std::size_t start = (current_line >= 50) ? current_line - 50 : 0;

    std::string pattern_str = R"(\b(?:int|long|short|char|size_t|unsigned)\s+)" +
                              var_name + R"(\s*=\s*([^;]+)\s*;)";
    std::regex init_pattern(pattern_str);

    for (std::size_t i = start; i < current_line; ++i) {
        std::smatch m;
        if (std::regex_search(lines[i], m, init_pattern)) {
            return trim(m[1].str());
        }
    }

    return std::nullopt;
}

bool variable_was_modified(
    const std::vector<std::string>& lines,
    std::size_t init_line,
    std::size_t use_line,
    const std::string& var_name) {

    std::string pattern_str = R"(\b)" + var_name + R"(\s*(?:=|\+=|-=|\*=|/=|\+\+|--))";
    std::regex modify_pattern(pattern_str);

    for (std::size_t i = init_line + 1; i < use_line; ++i) {
        if (std::regex_search(lines[i], modify_pattern)) {
            return true;
        }
    }

    return false;
}

bool variable_tainted_by_input(
    const std::vector<std::string>& lines,
    std::size_t current_line,
    const std::string& var_name) {

    // Find initialization line
    std::size_t start = (current_line >= 50) ? current_line - 50 : 0;
    std::size_t init_line = start;

    std::string init_pattern_str = R"(\b(?:int|long|short|char|size_t|unsigned)\s+)" +
                                    var_name + R"(\s*=)";
    std::regex init_pattern(init_pattern_str);

    for (std::size_t i = start; i < current_line; ++i) {
        if (std::regex_search(lines[i], init_pattern)) {
            init_line = i;
            break;
        }
    }

    std::string input_pattern_str =
        R"((?:scanf|fscanf|sscanf|gets|fgets|getline|read)\s*\([^)]*&)" + var_name + R"(\b)";
    std::regex input_pattern(input_pattern_str);

    std::string cin_pattern_str = R"(cin\s*>>\s*)" + var_name + R"(\b)";
    std::regex cin_pattern(cin_pattern_str);

    for (std::size_t i = init_line + 1; i < current_line; ++i) {
        if (std::regex_search(lines[i], input_pattern) ||
            std::regex_search(lines[i], cin_pattern)) {
            return true;
        }
    }

    return false;
}

bool is_function_parameter(
    const std::vector<std::string>& lines,
    std::size_t current_line,
    const std::string& var_name,
    const std::string& function_name) {

    std::size_t start = (current_line >= 20) ? current_line - 20 : 0;

    std::string pattern_str = function_name + R"(\s*\([^)]*\b)" + var_name + R"(\b[^)]*\))";
    std::regex param_pattern(pattern_str);

    for (std::size_t i = start; i < current_line; ++i) {
        if (std::regex_search(lines[i], param_pattern)) {
            return true;
        }
    }

    return false;
}

bool function_called_with_safe_constants(
    const std::vector<std::string>& lines,
    const std::string& function_name) {

    std::string pattern_str = function_name + R"(\s*\(([^)]+)\))";
    std::regex call_pattern(pattern_str);

    bool found_any_call = false;
    bool all_calls_safe = true;

    for (const auto& line : lines) {
        std::smatch m;
        if (std::regex_search(line, m, call_pattern)) {
            found_any_call = true;

            std::string args = m[1].str();

            std::vector<std::string> arg_list;
            std::stringstream ss(args);
            std::string arg;
            while (std::getline(ss, arg, ',')) {
                arg_list.push_back(trim(arg));
            }

            for (const auto& argument : arg_list) {
                auto val = evaluate_constant_expression(argument);
                if (!val.has_value()) {
                    all_calls_safe = false;
                    break;
                }

                constexpr int64_t SAFE_MIN = -10000;
                constexpr int64_t SAFE_MAX = 10000;
                if (*val < SAFE_MIN || *val > SAFE_MAX) {
                    all_calls_safe = false;
                    break;
                }
            }

            if (!all_calls_safe) {
                break;
            }
        }
    }

    return found_any_call && all_calls_safe;
}

bool is_variable_safe_constant(
    const std::vector<std::string>& lines,
    std::size_t current_line,
    const std::string& var_name) {

    if (variable_tainted_by_input(lines, current_line, var_name)) {
        return false;
    }

    auto init_value = find_variable_initialization(lines, current_line, var_name);
    if (!init_value.has_value()) {
        return false; 
    }

    auto val = evaluate_constant_expression(*init_value);
    if (!val.has_value()) {
        return false;
    }

    constexpr int64_t SAFE_MIN = -10000;
    constexpr int64_t SAFE_MAX = 10000;

    return (*val >= SAFE_MIN && *val <= SAFE_MAX);
}

bool has_overflow_check_before(const std::vector<std::string>& lines,
                                std::size_t current_line,
                                const std::string& var1,
                                const std::string& var2,
                                const std::string& operation) {
    
                                    std::size_t start = (current_line >= 10) ? current_line - 10 : 0;

    for (std::size_t i = start; i < current_line; ++i) {
        std::string line = lines[i];

        if (operation == "*" && line.find("__builtin_mul_overflow") != std::string::npos) {
            if (line.find(var1) != std::string::npos || line.find(var2) != std::string::npos) {
                return true;
            }
        }
        if (operation == "+" && line.find("__builtin_add_overflow") != std::string::npos) {
            if (line.find(var1) != std::string::npos || line.find(var2) != std::string::npos) {
                return true;
            }
        }
        if (operation == "-" && line.find("__builtin_sub_overflow") != std::string::npos) {
            if (line.find(var1) != std::string::npos || line.find(var2) != std::string::npos) {
                return true;
            }
        }

        if (operation == "*") {
            std::regex mul_check_re(
                R"(if\s*\([^)]*\b)" + var1 + R"(\s*>\s*(INT_MAX|SIZE_MAX|UINT_MAX)\s*/\s*\b)" + var2 + R"([^)]*\))");
            std::regex mul_check_re2(
                R"(if\s*\([^)]*\b)" + var2 + R"(\s*>\s*(INT_MAX|SIZE_MAX|UINT_MAX)\s*/\s*\b)" + var1 + R"([^)]*\))");
            if (std::regex_search(line, mul_check_re) || std::regex_search(line, mul_check_re2)) {
                return true;
            }
        }

        if (operation == "+") {
            std::regex add_check_re(
                R"(if\s*\([^)]*\b)" + var1 + R"(\s*>\s*(INT_MAX|SIZE_MAX|UINT_MAX)\s*-\s*\b)" + var2 + R"([^)]*\))");
            std::regex add_check_re2(
                R"(if\s*\([^)]*\b)" + var2 + R"(\s*>\s*(INT_MAX|SIZE_MAX|UINT_MAX)\s*-\s*\b)" + var1 + R"([^)]*\))");
            if (std::regex_search(line, add_check_re) || std::regex_search(line, add_check_re2)) {
                return true;
            }
        }

        if (operation == "-") {
            std::regex sub_check_re(
                R"(if\s*\([^)]*\b)" + var2 + R"(\s*>\s*\b)" + var1 + R"([^)]*\))");
            if (std::regex_search(line, sub_check_re)) {
                return true;
            }
        }
    }

    return false;
}

bool has_range_check_for_variable(const std::vector<std::string>& lines,
                                   std::size_t current_line,
                                   const std::string& var) {

    std::size_t start = (current_line >= 10) ? current_line - 10 : 0;

    std::size_t end = std::min(current_line + 5, lines.size());

    for (std::size_t i = start; i < end; ++i) {
        std::string line = lines[i];

        if (var.empty()) {
            // Look for any range check pattern
            if (line.find("if") != std::string::npos &&
                (line.find("<") != std::string::npos ||
                 line.find(">") != std::string::npos) &&
                std::regex_search(line, std::regex(R"(\d+)"))) {
                return true;
            }
            continue;
        }

        std::regex range_check_re(
            R"(if\s*\([^)]*\b)" + var + R"(\s*(<|>|<=|>=)\s*\d+[^)]*\))");
        if (std::regex_search(line, range_check_re)) {
            return true;
        }

        std::regex range_check_re2(
            R"(if\s*\([^)]*\b)" + var + R"(\s*(<|>|<=|>=)\s*[A-Z_][A-Z0-9_]*[^)]*\))");
        if (std::regex_search(line, range_check_re2)) {
            return true;
        }

        if (line.find("if") != std::string::npos && line.find(var) != std::string::npos &&
            (line.find("<") != std::string::npos || line.find(">") != std::string::npos)) {
            return true;
        }

        if (line.find("assert") != std::string::npos && line.find(var) != std::string::npos &&
            (line.find("<") != std::string::npos || line.find(">") != std::string::npos)) {
            return true;
        }
    }

    return false;
}

bool has_errno_check_after(const std::vector<std::string>& lines,
                            std::size_t current_line) {
    std::size_t end = std::min(current_line + 5, lines.size());

    for (std::size_t i = current_line; i < end; ++i) {
        std::string line = lines[i];

        if (line.find("errno") != std::string::npos &&
            line.find("ERANGE") != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool is_using_calloc(const std::string& code) {
    return code.find("calloc") != std::string::npos;
}

std::string extract_first_argument(const std::string& code, const std::string& func_name) {
    std::size_t pos = code.find(func_name + "(");
    if (pos == std::string::npos) {
        return "";
    }

    pos += func_name.length() + 1;

    while (pos < code.length() && std::isspace(code[pos])) {
        pos++;
    }

    std::string arg;
    int paren_depth = 0;
    bool in_string = false;
    bool escape = false;

    while (pos < code.length()) {
        char c = code[pos];

        if (escape) {
            arg += c;
            escape = false;
            pos++;
            continue;
        }

        if (c == '\\' && in_string) {
            escape = true;
            arg += c;
            pos++;
            continue;
        }

        if (c == '"') {
            in_string = !in_string;
            arg += c;
            pos++;
            continue;
        }

        if (!in_string) {
            if (c == '(') {
                paren_depth++;
            } else if (c == ')') {
                if (paren_depth == 0) {
                    break;
                }
                paren_depth--;
            } else if (c == ',' && paren_depth == 0) {
                break;
            }
        }

        arg += c;
        pos++;
    }

    size_t start = 0;
    while (start < arg.length() && std::isspace(arg[start])) {
        start++;
    }
    size_t end = arg.length();
    while (end > start && std::isspace(arg[end - 1])) {
        end--;
    }

    return arg.substr(start, end - start);
}

}


Findings SourceDetector::analyze_path(const std::string& path_str) const {
    Findings out;
    fs::path root(path_str);

    if (!fs::exists(root)) {
        add_source_finding(out,
                           "SRC_PATH_NOT_FOUND",
                           Severity::Info,
                           "Source path does not exist: " + path_str,
                           path_str,
                           0,
                           "Check the path or adjust SentinelX arguments.");
        return out;
    }

    auto analyze_file = [&out](const fs::path& file) {
        const std::string file_str = file.string();
        bool in_block_comment = false;
        int  brace_depth = 0;

        std::vector<std::string> lines;
        try {
            lines = read_lines(file_str);
        } catch (const std::exception& ex) {
            add_source_finding(out,
                               "SRC_READ_ERROR",
                               Severity::Info,
                               std::string("Failed to read file: ") + ex.what(),
                               file_str,
                               0,
                               "Check file permissions.");
            return;
        }

        static const std::vector<std::string> dangerous_calls = {
            "strcpy", "wcscpy", "strcat", "wcscat",
            "gets", "sprintf", "vsprintf"
        };
        static const std::vector<std::string> scanf_like = {
            "scanf", "fscanf", "sscanf"
        };
        static const std::vector<std::string> printf_like = {
            "printf", "fprintf", "vprintf", "vfprintf"
        };

        static const std::vector<std::string> command_exec_funcs = {
            "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve"
        };

        sx::BufferFSM buffer_fsm;
        std::string current_function = "<unknown>";

        BufferAnalyzer buffer_analyzer;
        TaintAnalyzer taint_analyzer;

        std::string full_code;
        bool temp_in_block_comment = false;
        for (const auto& line : lines) {
            std::string cleaned = strip_comments_preserve_strings(line, temp_in_block_comment);
            full_code += cleaned + "\n";
        }

        buffer_analyzer.parse_declarations(full_code);
        taint_analyzer.analyze_code(full_code);

        std::set<std::string> wrapper_functions;
        {
            std::string temp_current_func;
            static const std::regex func_decl_re(
                R"(\b(?:void|int|char\*?|struct\s+\w+\*?)\s+([A-Za-z_]\w*)\s*\()");

            for (const auto& line : lines) {
                std::string code = strip_comments_preserve_strings(line, temp_in_block_comment);
                code = trim(code);

                std::smatch func_match;
                if (std::regex_search(code, func_match, func_decl_re)) {
                    temp_current_func = func_match[1].str();
                }

                if (!temp_current_func.empty() &&
                    temp_current_func.find("safe_") != 0 &&
                    temp_current_func.find("test_") != 0 &&
                    temp_current_func.find("example_") != 0 &&
                    temp_current_func.find("demo_") != 0 &&
                    temp_current_func.find("vuln_") != 0) {

                    for (const auto& dangerous : dangerous_calls) {
                        if (code.find(dangerous + "(") != std::string::npos) {
                            wrapper_functions.insert(temp_current_func);
                            break;
                        }
                    }
                }
            }
        }

        static const std::regex char_array_decl_re(
            R"(\bchar\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\])");

        static const std::regex memcpy_re(
            R"(\bmemcpy\s*\(\s*([A-Za-z_]\w*)\s*,\s*[^,]+,\s*(\d+)\s*\))");
        static const std::regex read_re(
            R"(\bread\s*\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*,\s*(\d+)\s*\))");

        static const std::vector<std::string> unsafe_conv_funcs = {
            "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull"
        };
        
        static const std::regex arithmetic_op_re(
            R"(\b(\w+)\s*=\s*\b(\w+)\s*([\+\-\*])\s*\b(\w+)\s*;)");

        static const std::regex malloc_mult_re(
            R"(\b(malloc|calloc|realloc|new)\s*\(\s*(\w+)\s*\*\s*(\w+)\s*\))");

        const std::size_t LARGE_STACK_THRESHOLD = 1024; // bytes

        for (std::size_t i = 0; i < lines.size(); ++i) {
            const std::size_t line_no = i + 1;
            const std::string& raw_line = lines[i];

            if (raw_line.find("SENTINELX_IGNORE") != std::string::npos ||
                raw_line.find("SENTINELX:IGNORE") != std::string::npos) {
                continue;
            }

            std::string code = strip_comments_preserve_strings(raw_line,
                                                               in_block_comment);
            code = trim(code);
            if (code.empty()) {
                for (char c : raw_line) {
                    if (c == '{') ++brace_depth;
                    else if (c == '}' && brace_depth > 0) --brace_depth;
                }
                continue;
            }

            bool inside_block = (brace_depth > 0) ||
                                (code.find('{') != std::string::npos);

            std::string func_name = extract_function_name(code);
            if (!func_name.empty()) {
                current_function = func_name;
            }

            for (const auto& func : dangerous_calls) {
                if (contains_function_call(code, func)) {
                    Severity sev = Severity::High;
                    Confidence conf = Confidence::High;

                    if (func == "gets") {
                        sev = Severity::Critical;
                        conf = Confidence::Certain;
                    } else if (func == "strcpy" || func == "strcat") {
                        std::regex call_re(func + R"(\s*\(\s*(\w+)\s*,\s*([^)]+)\s*\))");
                        std::smatch m;
                        if (std::regex_search(code, m, call_re)) {
                            std::string dest = m[1].str();
                            std::string src = m[2].str();
                            src = trim(src);

                            std::size_t src_size = 0;
                            if (src.front() == '"' && src.back() == '"') {
                                src_size = buffer_analyzer.estimate_string_size(src);
                            } else {
                                auto size_opt = buffer_analyzer.get_buffer_size(src);
                                if (size_opt) {
                                    src_size = *size_opt;
                                }
                            }

                            sx::BufferKey key{file_str, current_function, dest};
                            sx::SourceLocation loc{file_str, static_cast<int>(line_no)};

                            if (func == "strcpy") {
                                buffer_fsm.on_reset(key, loc);
                                if (src_size > 0) {
                                    buffer_fsm.on_write(key, src_size, loc);
                                }
                            } else {
                                if (src_size > 0) {
                                    buffer_fsm.on_write(key, src_size, loc);
                                }
                            }

                            if (buffer_fsm.state_of(key) == sx::BufferState::Tainted) {
                                conf = Confidence::Certain;
                                sev = Severity::Critical;
                            } else if (buffer_analyzer.is_safe_copy(dest, src)) {
                                conf = Confidence::Low;
                                sev = Severity::Info;
                            } else {
                                bool src_tainted = taint_analyzer.is_expression_tainted(src);
                                TaintSource src_source = taint_analyzer.get_expression_source(src);

                                if (src_source == TaintSource::CONSTANT) {
                                    conf = Confidence::Low;
                                    sev = Severity::Info;
                                } else if (src_tainted) {
                                    conf = Confidence::High;
                                    sev = Severity::Critical;
                                } else {
                                    conf = Confidence::Medium;
                                }
                            }
                        }
                    } else if (func == "sprintf" || func == "vsprintf") {
                        std::regex call_re(func + R"(\s*\(\s*(\w+)\s*,\s*)");
                        std::smatch m;
                        if (std::regex_search(code, m, call_re)) {
                            std::string dest = m[1].str();

                            size_t format_start = m.position() + m.length();
                            std::string format;
                            size_t format_end = format_start;

                            if (format_start < code.length() && code[format_start] == '"') {
                                // Find end of string literal
                                format_end = format_start + 1;
                                while (format_end < code.length()) {
                                    if (code[format_end] == '"' && code[format_end - 1] != '\\') {
                                        format_end++;
                                        break;
                                    }
                                    format_end++;
                                }
                                format = code.substr(format_start, format_end - format_start);
                            } else {
                                while (format_end < code.length() &&
                                       code[format_end] != ',' && code[format_end] != ')') {
                                    format_end++;
                                }
                                format = code.substr(format_start, format_end - format_start);
                            }
                            format = trim(format);

                            bool format_is_literal = (!format.empty() &&
                                                     format.front() == '"' &&
                                                     format.back() == '"');

                            std::string remaining = (format_end < code.length()) ? code.substr(format_end) : "";
                            size_t closing_paren = remaining.find(')');

                            bool all_args_safe = true;
                            if (closing_paren != std::string::npos) {
                                std::string args_str = remaining.substr(0, closing_paren);

                                size_t pos = 0;
                                while (pos < args_str.length()) {
                                    size_t comma = args_str.find(',', pos);
                                    size_t end_pos = (comma == std::string::npos) ? args_str.length() : comma;

                                    std::string arg = args_str.substr(pos, end_pos - pos);
                                    arg = trim(arg);

                                    if (!arg.empty()) {
                                        TaintSource arg_source = taint_analyzer.get_expression_source(arg);
                                        if (arg_source != TaintSource::CONSTANT &&
                                            arg_source != TaintSource::SANITIZED) {
                                            all_args_safe = false;

                                            if (taint_analyzer.is_expression_tainted(arg)) {
                                                conf = Confidence::High;
                                                sev = Severity::Critical;
                                                break;
                                            } else if (arg_source == TaintSource::UNKNOWN) {
                                                conf = Confidence::High;
                                                sev = Severity::High;
                                            }
                                        }
                                    }

                                    if (comma == std::string::npos) break;
                                    pos = comma + 1;
                                }
                            }

                            if (!format_is_literal) {
                                conf = Confidence::High;
                                sev = Severity::Critical;
                            } else {
                                bool has_tainted_args = false;
                                if (closing_paren != std::string::npos) {
                                    std::string args_str = remaining.substr(0, closing_paren);
                                    size_t pos = 0;
                                    while (pos < args_str.length()) {
                                        size_t comma = args_str.find(',', pos);
                                        size_t end_pos = (comma == std::string::npos) ? args_str.length() : comma;
                                        std::string arg = args_str.substr(pos, end_pos - pos);
                                        arg = trim(arg);
                                        if (!arg.empty() && taint_analyzer.is_expression_tainted(arg)) {
                                            has_tainted_args = true;
                                            break;
                                        }
                                        if (comma == std::string::npos) break;
                                        pos = comma + 1;
                                    }
                                }
                                
                                if (has_tainted_args) {
                                    conf = Confidence::High;
                                    sev = Severity::High;
                                } else {
                                    conf = Confidence::Medium;
                                    sev = Severity::High;
                                }
                            }
                        }
                    }

                    std::string msg =
                        "Call to potentially unsafe function '" + func + "' "
                        "without explicit bounds.";
                    std::string rec =
                        "Prefer bounded alternatives (e.g. strncpy, strlcpy, "
                        "snprintf) and ensure buffer size checks.";

                    std::string context = get_source_context(lines, line_no);

                    add_source_finding(out,
                                       "SRC_UNSAFE_CALL_" + func,
                                       sev,
                                       msg,
                                       file_str,
                                       line_no,
                                       rec,
                                       context,
                                       current_function,
                                       conf);
                }
            }

            for (const auto& wrapper_func : wrapper_functions) {
                if (wrapper_func == current_function) {
                    continue;
                }

                if (wrapper_func.find("safe_") == 0 ||
                    wrapper_func.find("test_") == 0 ||
                    wrapper_func.find("example_") == 0 ||
                    wrapper_func.find("demo_") == 0) {
                    continue;
                }

                std::size_t pos = 0;
                if (contains_function_call(code, wrapper_func, &pos)) {
                    std::string first_arg = extract_first_argument(code, wrapper_func);
                    bool is_safe_call = false;

                    if (!first_arg.empty() && first_arg.front() == '"' && first_arg.back() == '"') {

                        std::size_t literal_size = buffer_analyzer.estimate_string_size(first_arg);

                        if (literal_size > 0) {
                            std::regex func_body_re(
                                R"(\b)" + wrapper_func + R"(\s*\([^)]*\)\s*\{[^}]*char\s+\w+\s*\[\s*(\w+)\s*\])"
                            );
                            std::smatch match;
                            std::size_t max_safe_size = 32;

                            if (std::regex_search(full_code, match, func_body_re)) {
                                std::string buffer_size_str = match[1].str();

                                std::regex define_value_re(R"(#define\s+)" + buffer_size_str + R"(\s+(\d+))");
                                std::smatch define_match;
                                if (std::regex_search(full_code, define_match, define_value_re)) {
                                    max_safe_size = std::stoull(define_match[1].str());
                                } else if (std::all_of(buffer_size_str.begin(), buffer_size_str.end(), ::isdigit)) {
                                    max_safe_size = std::stoull(buffer_size_str);
                                }
                            }

                            if (literal_size <= max_safe_size) {
                                is_safe_call = true;
                            }
                        }
                    }

                    if (!is_safe_call) {
                        std::string msg =
                            "Call to user-defined function '" + wrapper_func +
                            "' which internally uses unsafe functions. "
                            "Ensure proper bounds checking.";
                        std::string rec =
                            "Review the '" + wrapper_func +
                            "' function implementation for buffer overflow risks. "
                            "Consider adding size parameters and bounds checking.";

                        std::string context = get_source_context(lines, line_no);

                        add_source_finding(out,
                                           "SRC_WRAPPER_CALL_" + wrapper_func,
                                           Severity::High,
                                           msg,
                                           file_str,
                                           line_no,
                                           rec,
                                           context,
                                           current_function,
                                           Confidence::Medium);
                    }
                }
            }

            for (const auto& func : scanf_like) {
                std::size_t pos = 0;
                if (contains_function_call(code, func, &pos) &&
                    scanf_format_has_unbounded_s(code, pos)) {

                    std::string msg =
                        "Use of '" + func +
                        "' with '%s' format specifier without width "
                        "may lead to buffer overflow.";
                    std::string rec =
                        "Specify maximum field width in the format string "
                        "or replace with safer input handling.";

                    std::string context = get_source_context(lines, line_no);

                    add_source_finding(out,
                                       "SRC_SCANF_UNBOUNDED",
                                       Severity::High,
                                       msg,
                                       file_str,
                                       line_no,
                                       rec,
                                       context,
                                       current_function,
                                       Confidence::High);
                }
            }

            for (const auto& func : printf_like) {
                std::size_t pos = 0;
                if (contains_function_call(code, func, &pos) &&
                    has_format_string_vulnerability(code, pos)) {

                    Severity sev = Severity::Critical;
                    Confidence conf = Confidence::High;

                    std::regex printf_re(func + R"(\s*\(\s*([^,)]+))");
                    std::smatch m;
                    if (std::regex_search(code, m, printf_re)) {
                        std::string fmt_arg = m[1].str();
                        fmt_arg = trim(fmt_arg);

                        if (taint_analyzer.is_expression_tainted(fmt_arg)) {
                            sev = Severity::Critical;
                            conf = Confidence::Certain;
                        } else if (taint_analyzer.get_expression_source(fmt_arg) == TaintSource::CONSTANT) {
                            conf = Confidence::Medium;
                        }
                    }

                    std::string msg =
                        "Format string vulnerability: '" + func +
                        "' called with non-literal first argument. "
                        "Attacker-controlled format string can lead to arbitrary code execution.";
                    std::string rec =
                        "Always use a string literal for the format argument: " +
                        func + "(\"%s\", user_input) instead of " + func + "(user_input).";

                    std::string context = get_source_context(lines, line_no);

                    add_source_finding(out,
                                       "SRC_FORMAT_STRING_VULN",
                                       sev,
                                       msg,
                                       file_str,
                                       line_no,
                                       rec,
                                       context,
                                       current_function,
                                       conf);
                }
            }

            for (const auto& func : command_exec_funcs) {
                if (contains_function_call(code, func)) {
                    Severity sev = Severity::Critical;
                    Confidence conf = Confidence::High;

                    std::regex cmd_re(func + R"(\s*\(\s*([^)]+)\s*\))");
                    std::smatch m;
                    bool is_tainted = false;

                    if (std::regex_search(code, m, cmd_re)) {
                        std::string cmd_arg = m[1].str();
                        cmd_arg = trim(cmd_arg);

                        if (cmd_arg.empty()) {
                            continue;
                        }

                        bool is_literal = (cmd_arg.length() >= 2 &&
                                         cmd_arg.front() == '"' && cmd_arg.back() == '"');

                        if (is_literal) {
                            continue;
                        }

                        if ((func == "execv" || func == "execl" || func == "execlp" ||
                             func == "execle" || func == "execvp" || func == "execve")) {
                            std::size_t comma = cmd_arg.find(',');
                            if (comma != std::string::npos) {
                                std::string path_arg = cmd_arg.substr(0, comma);
                                path_arg = trim(path_arg);
                                bool path_is_literal = (path_arg.length() >= 2 &&
                                                       path_arg.front() == '"' &&
                                                       path_arg.back() == '"');

                                std::string remaining_args = cmd_arg.substr(comma + 1);
                                bool has_variable_args = false;

                                size_t arg_pos = 0;
                                while (arg_pos < remaining_args.length()) {
                                    size_t next_comma = remaining_args.find(',', arg_pos);
                                    size_t end = (next_comma == std::string::npos) ? remaining_args.length() : next_comma;
                                    std::string arg = remaining_args.substr(arg_pos, end - arg_pos);
                                    arg = trim(arg);

                                    if (!arg.empty() && arg != "NULL") {
                                        bool is_string_lit = (arg.length() >= 2 &&
                                                            arg.front() == '"' && arg.back() == '"');
                                        if (!is_string_lit) {
                                            has_variable_args = true;
                                            break;
                                        }
                                    }

                                    if (next_comma == std::string::npos) break;
                                    arg_pos = next_comma + 1;
                                }

                                if (path_is_literal && !has_variable_args) {
                                    continue; 
                                } else if (path_is_literal && has_variable_args) {
                                    conf = Confidence::Medium;
                                }
                            }
                        }

                        bool has_validation = false;
                        bool has_strong_validation = false;
                        std::size_t start = (line_no >= 10) ? line_no - 10 : 0;
                        for (std::size_t j = start; j < line_no - 1; ++j) {
                            std::string prev_line = lines[j];
                            if ((prev_line.find("strcmp") != std::string::npos &&
                                 prev_line.find("== 0") != std::string::npos) ||
                                prev_line.find("if (!is_safe") != std::string::npos ||
                                prev_line.find("escape_") != std::string::npos ||
                                prev_line.find("_escape") != std::string::npos ||
                                (prev_line.find("return") != std::string::npos &&
                                 prev_line.find("//") == std::string::npos)) {
                                has_strong_validation = true;
                                break;
                            }
                            
                            if (prev_line.find("is_safe") != std::string::npos ||
                                prev_line.find("validate") != std::string::npos ||
                                prev_line.find("whitelist") != std::string::npos ||
                                prev_line.find("isalnum") != std::string::npos) {
                                has_validation = true;
                                conf = Confidence::Medium;
                            }
                        }

                        if (has_strong_validation) {
                            continue;
                        }

                        if (taint_analyzer.is_expression_tainted(cmd_arg)) {
                            is_tainted = true;
                            if (!has_validation) {
                                conf = Confidence::Certain;
                            }
                        } else if (cmd_arg.find("argv") != std::string::npos ||
                                   cmd_arg.find("getenv") != std::string::npos) {
                            is_tainted = true;
                            if (!has_validation) {
                                conf = Confidence::Certain;
                            }
                        } else if (!is_literal) {
                            is_tainted = true;
                            conf = Confidence::Medium;
                        }
                    }

                    if (is_tainted) {
                        std::string msg =
                            "Command injection vulnerability: '" + func +
                            "' called with potentially user-controlled argument. "
                            "Attacker can execute arbitrary system commands.";
                        std::string rec =
                            "Avoid using " + func + " with user input. "
                            "If necessary, use whitelist validation and proper escaping. "
                            "Consider using safer alternatives like execve() with argument arrays.";

                        std::string context = get_source_context(lines, line_no);

                        add_source_finding(out,
                                           "SRC_COMMAND_INJECTION",
                                           sev,
                                           msg,
                                           file_str,
                                           line_no,
                                           rec,
                                           context,
                                           current_function,
                                           conf);
                    }
                }
            }

            for (const auto& func : unsafe_conv_funcs) {
                if (contains_function_call(code, func)) {
                    bool is_strtol_family = (func == "strtol" || func == "strtoul" ||
                                            func == "strtoll" || func == "strtoull");
                    if (is_strtol_family && has_errno_check_after(lines, line_no - 1)) {
                        continue;
                    }

                    bool is_atoi_family = (func == "atoi" || func == "atol" || func == "atoll");
                    if (is_atoi_family) {
                        std::regex atoi_assign_re(R"(\b(\w+)\s*=\s*)" + func + R"(\s*\()");
                        std::smatch m;
                        if (std::regex_search(code, m, atoi_assign_re)) {
                            std::string var_name = m[1].str();
                            if (has_range_check_for_variable(lines, line_no, var_name)) {
                                continue;
                            }
                        }
                    }

                    std::string msg =
                        "Use of '" + func + "' without proper error checking may lead to integer overflow.";
                    std::string rec =
                        "Use safe alternatives with error checking (strtol with errno) or "
                        "use safe integer conversion libraries.";

                    Severity sev = Severity::High;
                    if (is_atoi_family) {
                        sev = Severity::Critical;
                    }

                    std::string context = get_source_context(lines, line_no);

                    add_source_finding(out,
                                       "SRC_INTEGER_OVERFLOW_" + func,
                                       sev,
                                       msg,
                                       file_str,
                                       line_no,
                                       rec,
                                       context,
                                       current_function);
                }
            }
            
            std::string::const_iterator search_start(code.cbegin());
            std::smatch m_arith;
            while (std::regex_search(search_start, code.cend(), m_arith, arithmetic_op_re)) {
                std::string var = m_arith[1];
                std::string var1 = m_arith[2];
                std::string op = m_arith[3];
                std::string var2 = m_arith[4];

                std::string operation_name;
                Severity sev = Severity::High;

                if (op == "*") {
                    operation_name = "Multiplication";
                    sev = Severity::High;
                } else if (op == "+") {
                    operation_name = "Addition";
                    sev = Severity::Warning;
                } else if (op == "-") {
                    operation_name = "Subtraction";
                    sev = Severity::Warning;
                }

                if (!operation_name.empty()) {
                    if (is_constant_expression(var1, var2)) {
                        auto val1 = evaluate_constant_expression(var1);
                        auto val2 = evaluate_constant_expression(var2);

                        if (val1.has_value() && val2.has_value()) {
                            bool would_overflow = false;

                            if (op == "*") {
                                would_overflow = would_multiply_overflow(*val1, *val2);
                            } else if (op == "+") {
                                would_overflow = would_add_overflow(*val1, *val2);
                            } else if (op == "-") {
                                would_overflow = would_subtract_overflow(*val1, *val2);
                            }

                            if (!would_overflow) {
                                search_start = m_arith.suffix().first;
                                continue;
                            }

                            std::string msg =
                                operation_name + " of constants '" + var1 + "' " + op + " '" +
                                var2 + "' will cause integer overflow. Result: " + var + ".";
                            std::string rec =
                                "The constant expression '" + var1 + " " + op + " " + var2 +
                                "' results in integer overflow. Use larger integer types (long long) "
                                "or verify the calculation manually.";

                            std::string context = get_source_context(lines, line_no);

                            add_source_finding(out,
                                               "SRC_CONSTANT_OVERFLOW",
                                               Severity::Critical,
                                               msg,
                                               file_str,
                                               line_no,
                                               rec,
                                               context,
                                               current_function,
                                               Confidence::Certain);

                            search_start = m_arith.suffix().first;
                            continue;
                        }
                    }

                    if (has_overflow_check_before(lines, line_no - 1, var1, var2, op)) {
                        search_start = m_arith.suffix().first;
                        continue;
                    }

                    if (has_range_check_for_variable(lines, line_no - 1, var1) ||
                        has_range_check_for_variable(lines, line_no - 1, var2)) {
                        search_start = m_arith.suffix().first;
                        continue;
                    }

                    auto val1_literal = evaluate_constant_expression(var1);
                    auto val2_literal = evaluate_constant_expression(var2);

                    bool var1_is_literal = val1_literal.has_value();
                    bool var2_is_literal = val2_literal.has_value();

                    bool var1_safe = var1_is_literal || is_variable_safe_constant(lines, line_no - 1, var1);
                    bool var2_safe = var2_is_literal || is_variable_safe_constant(lines, line_no - 1, var2);

                    std::optional<int64_t> val1, val2;

                    if (var1_is_literal) {
                        val1 = val1_literal;
                    } else if (is_variable_safe_constant(lines, line_no - 1, var1)) {
                        auto init1 = find_variable_initialization(lines, line_no - 1, var1);
                        if (init1.has_value()) {
                            val1 = evaluate_constant_expression(*init1);
                        }
                    }

                    if (var2_is_literal) {
                        val2 = val2_literal;
                    } else if (is_variable_safe_constant(lines, line_no - 1, var2)) {
                        auto init2 = find_variable_initialization(lines, line_no - 1, var2);
                        if (init2.has_value()) {
                            val2 = evaluate_constant_expression(*init2);
                        }
                    }

                    // If both operands are safe (literals or safe variables), check for overflow
                    if (var1_safe && var2_safe && val1.has_value() && val2.has_value()) {
                        bool would_overflow = false;

                        if (op == "*") {
                            would_overflow = would_multiply_overflow(*val1, *val2);
                        } else if (op == "+") {
                            would_overflow = would_add_overflow(*val1, *val2);
                        } else if (op == "-") {
                            would_overflow = would_subtract_overflow(*val1, *val2);
                        }

                        // If safe and won't overflow, skip warning
                        if (!would_overflow) {
                            search_start = m_arith.suffix().first;
                            continue;
                        }
                    }

                    // NEW: Check if operands are function parameters
                    // For parameters, we skip warnings as we can't easily determine call-site values
                    // without full interprocedural analysis
                    bool var1_is_param = is_function_parameter(lines, line_no - 1, var1, current_function);
                    bool var2_is_param = is_function_parameter(lines, line_no - 1, var2, current_function);

                    // If both operands are function parameters, skip warning
                    // (user should add overflow checks if function can be called with large values)
                    if (var1_is_param && var2_is_param) {
                        search_start = m_arith.suffix().first;
                        continue;
                    }

                    std::string msg =
                        operation_name + " operation on '" + var + "' without overflow check.";
                    std::string rec =
                        "Use overflow-checked arithmetic operations (__builtin_add_overflow, "
                        "__builtin_sub_overflow, __builtin_mul_overflow, or SafeInt library).";

                    std::string context = get_source_context(lines, line_no);

                    add_source_finding(out,
                                       "SRC_ARITHMETIC_OVERFLOW",
                                       sev,
                                       msg,
                                       file_str,
                                       line_no,
                                       rec,
                                       context,
                                       current_function);
                }

                search_start = m_arith.suffix().first;
            }
            
            std::string::const_iterator search_start_malloc(code.cbegin());
            std::smatch m_malloc;
            while (std::regex_search(search_start_malloc, code.cend(), m_malloc, malloc_mult_re)) {
                std::string func = m_malloc[1];
                std::string var1 = m_malloc[2];
                std::string var2 = m_malloc[3];

                if (func == "calloc") {
                    search_start_malloc = m_malloc.suffix().first;
                    continue;
                }

                if (is_constant_expression(var1, var2)) {
                    auto val1 = evaluate_constant_expression(var1);
                    auto val2 = evaluate_constant_expression(var2);

                    if (val1.has_value() && val2.has_value()) {
                        bool would_overflow = would_multiply_overflow(*val1, *val2);

                        if (!would_overflow) {
                            search_start_malloc = m_malloc.suffix().first;
                            continue;
                        }

                        std::string msg =
                            "Memory allocation " + func + "(" + var1 + " * " + var2 +
                            ") will cause integer overflow, resulting in undersized allocation.";
                        std::string rec =
                            "The constant expression '" + var1 + " * " + var2 +
                            "' results in integer overflow. Use calloc(" + var1 + ", " + var2 +
                            ") or larger integer types for size calculation.";

                        std::string context = get_source_context(lines, line_no);

                        add_source_finding(out,
                                           "SRC_ALLOCATION_CONSTANT_OVERFLOW",
                                           Severity::Critical,
                                           msg,
                                           file_str,
                                           line_no,
                                           rec,
                                           context,
                                           current_function,
                                           Confidence::Certain);

                        search_start_malloc = m_malloc.suffix().first;
                        continue;
                    }
                }

                if (has_overflow_check_before(lines, line_no - 1, var1, var2, "*")) {
                    search_start_malloc = m_malloc.suffix().first;
                    continue;
                }

                if (has_range_check_for_variable(lines, line_no - 1, var1) ||
                    has_range_check_for_variable(lines, line_no - 1, var2)) {
                    search_start_malloc = m_malloc.suffix().first;
                    continue;
                }

                std::string msg =
                    "Memory allocation with size calculation may lead to integer overflow.";
                std::string rec =
                    "Use overflow-checked multiplication or use calloc for multiplication cases.";

                std::string context = get_source_context(lines, line_no);

                add_source_finding(out,
                                   "SRC_ALLOCATION_OVERFLOW",
                                   Severity::Critical,
                                   msg,
                                   file_str,
                                   line_no,
                                   rec,
                                   context,
                                   current_function);

                search_start_malloc = m_malloc.suffix().first;
            }

            // NEW: Check for integer overflow in variable initialization
            // Pattern: int var = large_constant;
            std::regex init_overflow_re(R"(\b(?:int|long|short|char|size_t)\s+(\w+)\s*=\s*([^;]+)\s*;)");
            std::smatch m_init;
            if (std::regex_search(code, m_init, init_overflow_re)) {
                std::string var_name = m_init[1].str();
                std::string init_value = trim(m_init[2].str());

                auto val = evaluate_constant_expression(init_value);
                if (val.has_value()) {
                    constexpr int64_t INT32_MAX_VAL = std::numeric_limits<int32_t>::max();
                    constexpr int64_t INT32_MIN_VAL = std::numeric_limits<int32_t>::min();

                    if (*val > INT32_MAX_VAL || *val < INT32_MIN_VAL) {
                        std::string msg =
                            "Variable '" + var_name + "' initialized with constant " + init_value +
                            " which exceeds int range (" + std::to_string(INT32_MIN_VAL) + " to " +
                            std::to_string(INT32_MAX_VAL) + "). Value will overflow.";
                        std::string rec =
                            "Use 'long long' type instead of 'int', or use a smaller constant value that fits in int range.";

                        std::string context = get_source_context(lines, line_no);

                        add_source_finding(out,
                                           "SRC_VARIABLE_INIT_OVERFLOW",
                                           Severity::Critical,
                                           msg,
                                           file_str,
                                           line_no,
                                           rec,
                                           context,
                                           current_function,
                                           Confidence::Certain);
                    }
                }
            }

            // NEW: Check for integer overflow in function calls with constant arguments
            // Pattern: function_name(arg1, arg2, ...)
            std::regex func_call_re(R"((\w+)\s*\(([^)]+)\))");
            std::smatch m_call;
            if (std::regex_search(code, m_call, func_call_re)) {
                std::string func_name = m_call[1].str();
                std::string args_str = m_call[2].str();

                // Skip standard library functions
                static const std::set<std::string> skip_funcs = {
                    "printf", "fprintf", "sprintf", "snprintf", "scanf", "fscanf", "sscanf",
                    "strlen", "strcmp", "strcpy", "strcat", "malloc", "calloc", "free",
                    "memcpy", "memset", "fopen", "fclose", "fread", "fwrite"
                };

                if (skip_funcs.find(func_name) == skip_funcs.end()) {
                    std::vector<std::string> args;
                    std::stringstream ss(args_str);
                    std::string arg;
                    while (std::getline(ss, arg, ',')) {
                        args.push_back(trim(arg));
                    }

                    for (const auto& argument : args) {
                        auto val = evaluate_constant_expression(argument);
                        if (val.has_value()) {
                            constexpr int64_t INT32_MAX_VAL = std::numeric_limits<int32_t>::max();
                            constexpr int64_t INT32_MIN_VAL = std::numeric_limits<int32_t>::min();

                            if (*val > INT32_MAX_VAL || *val < INT32_MIN_VAL) {
                                std::string msg =
                                    "Function '" + func_name + "' called with constant argument " +
                                    argument + " which exceeds int range. Argument will overflow.";
                                std::string rec =
                                    "Use a smaller constant that fits in int range, or change the function parameter type to 'long long'.";

                                std::string context = get_source_context(lines, line_no);

                                add_source_finding(out,
                                                   "SRC_FUNCTION_ARG_OVERFLOW",
                                                   Severity::Critical,
                                                   msg,
                                                   file_str,
                                                   line_no,
                                                   rec,
                                                   context,
                                                   current_function,
                                                   Confidence::Certain);
                                break; // Only report once per function call
                            }
                        }
                    }
                }
            }


            if (inside_block) {
                std::smatch m;
                if (std::regex_search(code, m, char_array_decl_re)) {
                    std::string buf_name = m[1].str();
                    std::size_t size = 0;
                    try {
                        size = static_cast<std::size_t>(std::stoull(m[2].str()));
                    } catch (...) {
                        size = 0;
                    }

                    sx::BufferKey key{file_str, current_function, buf_name};
                    sx::SourceLocation loc{file_str, static_cast<int>(line_no)};
                    buffer_fsm.on_declare(key, size, loc);

                    if (size >= LARGE_STACK_THRESHOLD) {
                        std::string msg =
                            "Large stack buffer '" + buf_name + "[" +
                            m[2].str() + "]' may contribute to stack overflow.";
                        std::string rec =
                            "Consider using dynamic allocation (heap) or "
                            "reducing buffer size.";

                        std::string context = get_source_context(lines, line_no);

                        add_source_finding(out,
                                           "SRC_LARGE_STACK_BUFFER",
                                           Severity::Warning,
                                           msg,
                                           file_str,
                                           line_no,
                                           rec,
                                           context,
                                           current_function);
                    }
                }

                {
                    std::smatch m;
                    if (std::regex_search(code, m, memcpy_re)) {
                        std::string dest = m[1].str();
                        std::size_t bytes = 0;
                        try {
                            bytes = static_cast<std::size_t>(std::stoull(m[2].str()));
                        } catch (...) {
                            bytes = 0;
                        }

                        sx::BufferKey key{file_str, current_function, dest};
                        sx::SourceLocation loc{file_str, static_cast<int>(line_no)};
                        buffer_fsm.on_write(key, bytes, loc);

                        if (buffer_fsm.state_of(key) == sx::BufferState::Tainted) {
                            std::string msg =
                                "Write of " + std::to_string(bytes) +
                                " bytes into buffer '" + dest +
                                "' may exceed its declared size.";
                            std::string rec =
                                "Ensure memcpy size does not exceed "
                                "destination buffer size.";

                            std::string context = get_source_context(lines, line_no);

                            add_source_finding(out,
                                               "SRC_BUFFER_OVERFLOW_MEMCPY",
                                               Severity::High,
                                               msg,
                                               file_str,
                                               line_no,
                                               rec,
                                               context,
                                               current_function);
                        }
                    }
                }

                {
                    std::smatch m;
                    if (std::regex_search(code, m, read_re)) {
                        std::string dest = m[1].str();
                        std::size_t bytes = 0;
                        try {
                            bytes = static_cast<std::size_t>(std::stoull(m[2].str()));
                        } catch (...) {
                            bytes = 0;
                        }

                        sx::BufferKey key{file_str, current_function, dest};
                        sx::SourceLocation loc{file_str, static_cast<int>(line_no)};
                        buffer_fsm.on_write(key, bytes, loc);

                        if (buffer_fsm.state_of(key) == sx::BufferState::Tainted) {
                            std::string msg =
                                "read() of " + std::to_string(bytes) +
                                " bytes into buffer '" + dest +
                                "' may exceed its declared size.";
                            std::string rec =
                                "Ensure read() third argument does not exceed "
                                "destination buffer size.";

                            std::string context = get_source_context(lines, line_no);

                            add_source_finding(out,
                                               "SRC_BUFFER_OVERFLOW_READ",
                                               Severity::High,
                                               msg,
                                               file_str,
                                               line_no,
                                               rec,
                                               context,
                                               current_function);
                        }
                    }
                }
            }

            {
                static const std::regex fgets_re(
                    R"(\bfgets\s*\(\s*([A-Za-z_]\w*)\s*,\s*(\d+)\s*,)");
                std::smatch m;
                if (std::regex_search(code, m, fgets_re)) {
                    std::string dest = m[1].str();
                    std::size_t read_size = 0;
                    try {
                        read_size = static_cast<std::size_t>(std::stoull(m[2].str()));
                    } catch (...) {
                        read_size = 0;
                    }

                    auto dest_size = buffer_analyzer.get_buffer_size(dest);

                    if (dest_size && read_size > *dest_size) {
                        std::string msg =
                            "fgets() reads " + std::to_string(read_size) +
                            " bytes into buffer '" + dest +
                            "' of size " + std::to_string(*dest_size) + ". "
                            "This will cause buffer overflow.";
                        std::string rec =
                            "Ensure fgets() size parameter does not exceed "
                            "destination buffer size. Use sizeof(" + dest + ") or " +
                            std::to_string(*dest_size) + " as the size parameter.";

                        std::string context = get_source_context(lines, line_no);

                        add_source_finding(out,
                                           "SRC_BUFFER_OVERFLOW_FGETS",
                                           Severity::Critical,
                                           msg,
                                           file_str,
                                           line_no,
                                           rec,
                                           context,
                                           current_function,
                                           Confidence::Certain);
                    } else if (read_size > 0 && !dest_size) {
                        if (read_size > 1024) {  // Arbitrary threshold for "large"
                            std::string msg =
                                "fgets() reads up to " + std::to_string(read_size) +
                                " bytes into buffer '" + dest +
                                "' of unknown size. May cause overflow.";
                            std::string rec =
                                "Ensure fgets() size parameter matches buffer size. "
                                "Use sizeof(" + dest + ") for the size parameter.";

                            std::string context = get_source_context(lines, line_no);

                            add_source_finding(out,
                                               "SRC_BUFFER_OVERFLOW_FGETS",
                                               Severity::High,
                                               msg,
                                               file_str,
                                               line_no,
                                               rec,
                                               context,
                                               current_function,
                                               Confidence::Medium);
                        }
                    }
                }
            }

            for (char c : code) {
                if (c == '{') ++brace_depth;
                else if (c == '}' && brace_depth > 0) --brace_depth;
            }
        }

        (void)buffer_fsm;
        (void)current_function;
    };

    if (fs::is_regular_file(root)) {
        if (is_source_file(root)) {
            analyze_file(root);
        }
    } else if (fs::is_directory(root)) {
        for (const auto& entry : fs::recursive_directory_iterator(root)) {
            if (entry.is_regular_file() && is_source_file(entry.path())) {
                analyze_file(entry.path());
            }
        }
    }

    return out;
}

Findings SourceDetector::analyze_path_with_call_graph(const std::string& path,
                                                       CallGraphAnalyzer& call_graph) const {
    Findings all_findings = analyze_path(path);

    Findings filtered_findings;

    for (auto& finding : all_findings) {
        const std::string& func_name = finding.source_location.function_name;

        bool is_reachable = call_graph.is_reachable(func_name);
        finding.is_in_reachable_function = is_reachable;

        if (config_.only_reachable_functions) {
            if (is_reachable) {
                filtered_findings.push_back(finding);
            } else if (config_.show_unused_function_warnings) {
                finding.severity = Severity::Info;
                finding.message = "[UNUSED FUNCTION] " + finding.message;
                finding.recommendation = "This function is not called from main or any entry point. " +
                                        finding.recommendation;
                filtered_findings.push_back(finding);
            }
        } else {
            filtered_findings.push_back(finding);
        }
    }

    return filtered_findings;
}


Findings BinaryDetector::analyze_binary(const std::string& path) const {
    Findings out;

#ifndef SENTINELX_USE_LIEF
    fs::path p(path);
    if (!fs::exists(p)) {
        add_binary_finding(out,
                           "BIN_PATH_NOT_FOUND",
                           Severity::Info,
                           "Binary path does not exist: " + path,
                           "unknown",
                           {},
                           0,
                           "Check the path or adjust SentinelX arguments.");
        return out;
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        add_binary_finding(out,
                           "BIN_READ_ERROR",
                           Severity::Info,
                           "Failed to open binary file: " + path,
                           "unknown",
                           {},
                           0,
                           "Check file permissions.");
        return out;
    }

    std::string content((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());

    static const std::vector<std::string> dangerous_imports = {
        "strcpy", "wcscpy", "strcat", "wcscat", "gets",
        "sprintf", "vsprintf", "printf", "fprintf", "vprintf", "vfprintf",
        "snprintf", "vsnprintf"
    };

    auto matches = rabin_karp_search(content, dangerous_imports);
    
    for (const auto& match : matches) {
        std::size_t pos = match.first;
        const std::string& d = match.second;
        
        std::string msg =
            "Binary contains reference to potentially unsafe function '" +
            d + "' at file offset " + to_hex64(static_cast<std::uint64_t>(pos)) + ".";
        
        std::string rec =
            "This is a heuristic scan without LIEF. "
            "Consider enabling LIEF for accurate disassembly and call-site analysis.";

        add_binary_finding(out,
                           "BIN_UNSAFE_BYTES_" + d,
                           Severity::Warning,
                           msg,
                           "unknown",
                           "raw",
                           static_cast<std::uint64_t>(pos),
                           rec);
    }

    if (out.empty()) {
        add_binary_finding(out,
                           "BIN_ANALYSIS_LIMITED",
                           Severity::Info,
                           "Binary analysis performed without LIEF; no obvious unsafe function names found.",
                           "unknown");
    }

    return out;
#else
    fs::path p(path);
    if (!fs::exists(p)) {
        add_binary_finding(out,
                           "BIN_PATH_NOT_FOUND",
                           Severity::Info,
                           "Binary path does not exist: " + path,
                           "unknown",
                           {},
                           0,
                           "Check the path or adjust SentinelX arguments.");
        return out;
    }

    BinaryParser parser;
    BinaryInfo info;
    try {
        info = parser.parse(path);
    } catch (const std::exception& ex) {
        add_binary_finding(out,
                           "BIN_PARSE_ERROR",
                           Severity::Info,
                           std::string("Failed to parse binary with LIEF: ") +
                               ex.what(),
                           "unknown",
                           {},
                           0,
                           "Ensure the file is a supported executable format.");
        return out;
    }

    static const std::vector<std::string> dangerous_imports = {
        "strcpy", "wcscpy", "strcat", "wcscat", "gets",
        "sprintf", "vsprintf", "printf", "fprintf", "vprintf", "vfprintf",
        "snprintf", "vsnprintf"
    };

    Disassembler disasm;

    disasm.load_binary(info.path);

    auto _text = disasm.disassemble_section(".text");
    if (_text.empty()) {
        _text = disasm.disassemble_section("__text");
    }

    for (const auto& imp : info.imported_functions) {
        std::string lower = to_lower(imp);

        bool is_dangerous = false;
        std::string dangerous_func;

        auto matches = rabin_karp_search(lower, dangerous_imports);
        if (!matches.empty()) {
            is_dangerous = true;
            dangerous_func = matches[0].second;
        }

        if (is_dangerous) {
            if (_text.empty()) {
                std::string msg =
                    "Binary imports potentially unsafe function '" + imp + "'.";
                std::string rec =
                    "Review all call sites of '" + imp +
                    "' and consider replacing with bounded alternatives. "
                    "(Note: Disassembly unavailable for this binary/architecture combination)";

                add_binary_finding(out,
                                   "BIN_UNSAFE_IMPORT_" + dangerous_func,
                                   Severity::Warning,
                                   msg,
                                   info.arch,
                                   "",
                                   0,
                                   rec,
                                   "");
            } else {
                std::vector<std::uint64_t> call_sites;

                for (const auto& inst : _text) {
                    if (inst.mnemonic == "call" || inst.mnemonic == "bl" || inst.mnemonic == "blx") {
                        if (inst.operands.find(imp) != std::string::npos) {
                            call_sites.push_back(inst.address);
                        }
                    }
                }

                for (std::uint64_t call_addr : call_sites) {
                    auto context_insts = disasm.get_context(call_addr, _text, 7, 7);

                    std::string func_name = disasm.find_function_name(info, call_addr);
                    std::uint64_t ret_addr = disasm.calculate_return_address(call_addr, context_insts);

                    bool is_printf_like = (dangerous_func == "printf" ||
                                          dangerous_func == "fprintf" ||
                                          dangerous_func == "vprintf" ||
                                          dangerous_func == "vfprintf" ||
                                          dangerous_func == "snprintf" ||
                                          dangerous_func == "vsnprintf");

                    if (is_printf_like && !context_insts.empty()) {
                        int format_arg_pos = 0;
                        if (dangerous_func == "fprintf" || dangerous_func == "vfprintf") {
                            format_arg_pos = 1; // fprintf(stream, format, ...)
                        } else if (dangerous_func == "snprintf" || dangerous_func == "vsnprintf") {
                            format_arg_pos = 2; // snprintf(buf, size, format, ...)
                        } else {
                            format_arg_pos = 0; // printf(format, ...)
                        }

                        bool likely_literal = is_format_arg_likely_literal(
                            context_insts, call_addr, info.arch, format_arg_pos);

                        if (likely_literal) {
                            continue;
                        }
                    }

                    std::string snippet;
                    std::uint64_t first_addr = 0;

                    if (!context_insts.empty()) {
                        first_addr = call_addr;
                    }

                    std::int64_t cumulative_stack = 0;
                    std::int64_t frame_size = 0;
                    bool found_frame_alloc = false;

                    for (const auto& inst : context_insts) {
                        snippet += to_hex64(inst.address);
                        snippet += ": ";
                        snippet += inst.text;

                        if (!found_frame_alloc && inst.mnemonic == "sub" &&
                            (inst.operands.find("sp") != std::string::npos ||
                             inst.operands.find("rsp") != std::string::npos)) {
                            frame_size = -inst.stack_delta;
                            found_frame_alloc = true;
                        }

                        if (inst.address == call_addr) {
                            snippet += "  <-- DANGEROUS CALL";
                        } else if (inst.stack_delta != 0) {
                            cumulative_stack += inst.stack_delta;
                            std::ostringstream delta_ss;
                            delta_ss << "  ; stack_delta: ";
                            if (inst.stack_delta > 0) {
                                delta_ss << "+";
                            }
                            delta_ss << "0x" << std::hex << std::abs(inst.stack_delta) << std::dec;
                            delta_ss << ", cumulative: 0x" << std::hex << std::abs(cumulative_stack) << std::dec;
                            snippet += delta_ss.str();
                        } else if (inst.mnemonic == "str" || inst.mnemonic == "mov") {
                            if (inst.operands.find("[sp") != std::string::npos ||
                                inst.operands.find("[rsp") != std::string::npos) {
                                snippet += "  ; buffer/local var on stack";
                            }
                        }

                        snippet += "\n";
                    }

                    if (frame_size > 0) {
                        std::ostringstream header_ss;
                        header_ss << "\n  Stack frame size: 0x" << std::hex << frame_size << std::dec
                                 << " (" << frame_size << " bytes)\n";
                        snippet = header_ss.str() + snippet;
                    }

                    Severity sev = Severity::Warning;
                    std::string msg =
                        "Call to potentially unsafe function '" + imp +
                        "' at address " + to_hex64(call_addr) + ".";

                    std::string rec =
                        "Review this call site of '" + imp +
                        "' and consider replacing with bounded alternatives.";

                    if (is_printf_like) {
                        sev = Severity::Critical;
                        msg = "Potential format string vulnerability: '" + imp +
                              "' at address " + to_hex64(call_addr) +
                              ". First argument does not appear to be a string literal.";
                        rec = "Verify that the format string is controlled and not user-supplied. "
                              "Use a literal format string when possible.";
                    }

                    Confidence conf = Confidence::Medium;
                    if (is_printf_like) {
                        conf = Confidence::High;
                    }

                    add_binary_finding(out,
                                       "BIN_UNSAFE_CALL_" + dangerous_func,
                                       sev,
                                       msg,
                                       info.arch,
                                       ".text",
                                       first_addr,
                                       rec,
                                       snippet,
                                       func_name,
                                       ret_addr,
                                       conf);
                }
            }
        }
    }

    return out;
#endif
}

}
