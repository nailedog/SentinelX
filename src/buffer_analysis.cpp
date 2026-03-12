#include "buffer_analysis.h"
#include <regex>
#include <algorithm>

namespace sentinel {

void BufferAnalyzer::register_buffer(const std::string& name, std::size_t size) {
    buffer_sizes_[name] = size;
}

std::optional<std::size_t> BufferAnalyzer::get_buffer_size(const std::string& name) const {
    auto it = buffer_sizes_.find(name);
    if (it != buffer_sizes_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::size_t BufferAnalyzer::estimate_string_size(const std::string& literal) const {
    if (literal.length() >= 2 && literal.front() == '"' && literal.back() == '"') {
        // Length includes \0: "hello" = 6 bytes (h,e,l,l,o,\0)
        // literal.length() = 7 (including quotes)
        // So: 7 - 2 (quotes) + 1 (\0) = 6
        return literal.length() - 2 + 1;
    }

    return 0;
}

bool BufferAnalyzer::is_safe_copy(const std::string& dest, const std::string& src) const {
    auto dest_size = get_buffer_size(dest);
    if (!dest_size) {
        return false;
    }

    std::size_t src_size = estimate_string_size(src);
    if (src_size > 0) {
        return *dest_size >= src_size;
    }

    auto src_buf_size = get_buffer_size(src);
    if (src_buf_size) {
        return *dest_size >= *src_buf_size;
    }

    return false;
}

void BufferAnalyzer::parse_declarations(const std::string& code) {
    std::unordered_map<std::string, std::size_t> defines;
    std::regex define_re(R"(#define\s+(\w+)\s+(\d+))");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), define_re);
         it != std::sregex_iterator(); ++it) {
        std::string name = (*it)[1].str();
        std::size_t value = std::stoull((*it)[2].str());
        defines[name] = value;
    }

    std::regex char_array_re(R"(char\s+(\w+)\s*\[\s*(\d+)\s*\])");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), char_array_re);
         it != std::sregex_iterator(); ++it) {
        std::string name = (*it)[1].str();
        std::size_t size = std::stoull((*it)[2].str());
        register_buffer(name, size);
    }

    std::regex char_array_define_re(R"(char\s+(\w+)\s*\[\s*(\w+)\s*\])");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), char_array_define_re);
         it != std::sregex_iterator(); ++it) {
        std::string name = (*it)[1].str();
        std::string define_name = (*it)[2].str();
        auto def_it = defines.find(define_name);
        if (def_it != defines.end()) {
            register_buffer(name, def_it->second);
        }
    }

    std::regex uchar_array_re(R"((?:unsigned\s+|signed\s+)?char\s+(\w+)\s*\[\s*(\d+)\s*\])");
    for (auto it = std::sregex_iterator(code.begin(), code.end(), uchar_array_re);
         it != std::sregex_iterator(); ++it) {
        std::string name = (*it)[1].str();
        std::size_t size = std::stoull((*it)[2].str());
        register_buffer(name, size);
    }
}

void BufferAnalyzer::clear() {
    buffer_sizes_.clear();
}

}