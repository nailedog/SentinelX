#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>

namespace sentinel {

/**
 * @brief Source of tainted (potentially dangerous) data
 */
enum class TaintSource {
    USER_INPUT,    // argv, scanf, gets, getenv, etc.
    FILE_INPUT,    // fread, fgets, etc.
    NETWORK,       // recv, recvfrom, etc.
    CONSTANT,      // String literals, numeric constants
    SANITIZED,     // Data that has been validated/sanitized
    UNKNOWN        // Unknown source
};

/**
 * @brief Tracks data flow to identify tainted variables
 */
class TaintAnalyzer {
public:
    TaintAnalyzer() = default;

    /**
     * @brief Mark a variable as tainted
     * @param var Variable name
     * @param source Source of the taint
     */
    void mark_tainted(const std::string& var, TaintSource source);

    /**
     * @brief Check if a variable is tainted
     * @param var Variable name
     * @return true if variable is from untrusted source
     */
    bool is_tainted(const std::string& var) const;

    /**
     * @brief Get the taint source for a variable
     * @param var Variable name
     * @return TaintSource if known, UNKNOWN otherwise
     */
    TaintSource get_source(const std::string& var) const;

    /**
     * @brief Propagate taint on assignment: dst = src
     * @param dst Destination variable
     * @param src Source variable
     */
    void propagate_taint(const std::string& dst, const std::string& src);

    /**
     * @brief Parse code to identify taint sources
     * @param code Source code to analyze
     */
    void analyze_code(const std::string& code);

    /**
     * @brief Clear all taint information
     */
    void clear();

    /**
     * @brief Check if a taint source is dangerous
     * @param source Taint source to check
     * @return true if source represents user-controllable input
     */
    static bool is_dangerous_source(TaintSource source);

    /**
     * @brief Check if an expression (not just variable) is tainted
     * @param expr Expression to check (e.g., "argv[1]", "getenv(\"X\")", etc.)
     * @return true if expression represents user-controllable input
     *
     * This checks direct usage patterns:
     * - argv[N] or argv[variable]
     * - getenv(...) calls
     * - Any variable marked as tainted
     */
    bool is_expression_tainted(const std::string& expr) const;

    /**
     * @brief Get taint source for an expression
     * @param expr Expression to analyze
     * @return TaintSource for the expression
     */
    TaintSource get_expression_source(const std::string& expr) const;

private:
    std::unordered_map<std::string, TaintSource> taint_map_;
    std::unordered_set<std::string> constant_arrays_;

    void analyze_user_input_sources(const std::string& code);
    void analyze_constant_sources(const std::string& code);
    void analyze_assignments(const std::string& code);
    void analyze_constant_arrays(const std::string& code);
    void analyze_function_parameters(const std::string& code);
};

} // namespace sentinel
