#pragma once

#include <string>
#include <unordered_map>
#include <optional>

namespace sentinel {

/**
 * @brief Analyzes buffer sizes to reduce false positives
 *
 * Tracks buffer declarations and their sizes to determine
 * if operations like strcpy are actually safe.
 */
class BufferAnalyzer {
public:
    BufferAnalyzer() = default;

    /**
     * @brief Register a buffer with its size
     * @param name Buffer variable name
     * @param size Size of the buffer in bytes
     */
    void register_buffer(const std::string& name, std::size_t size);

    /**
     * @brief Get the size of a registered buffer
     * @param name Buffer variable name
     * @return Optional size if buffer is known
     */
    std::optional<std::size_t> get_buffer_size(const std::string& name) const;

    /**
     * @brief Estimate the size of a string literal
     * @param literal String literal (e.g., "hello")
     * @return Size including null terminator
     */
    std::size_t estimate_string_size(const std::string& literal) const;

    /**
     * @brief Check if a copy operation is safe based on buffer sizes
     * @param dest Destination buffer name
     * @param src Source (variable name or string literal)
     * @return true if the copy is provably safe, false if unsafe or unknown
     */
    bool is_safe_copy(const std::string& dest, const std::string& src) const;

    /**
     * @brief Parse buffer declarations from code
     * @param code Source code to analyze
     */
    void parse_declarations(const std::string& code);

    /**
     * @brief Clear all registered buffers
     */
    void clear();

private:
    std::unordered_map<std::string, std::size_t> buffer_sizes_;
};

}
