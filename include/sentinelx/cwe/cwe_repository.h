#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace sentinelx {

/**
 * @brief CWE information structure
 */
struct CweInfo {
    std::string cwe_id;             // "CWE-120"
    int cwe_number;                 // 120
    std::string name;               // "Buffer Copy without Checking Size of Input"
    std::string description;        // Full description
    std::string extended_description;
    std::string severity;           // INFO, WARNING, HIGH, CRITICAL
    std::string likelihood;         // LOW, MEDIUM, HIGH
    std::string abstraction;        // Base, Variant, Class, etc.
    std::string structure;          // Simple, Chain, Composite
    std::string status;             // Draft, Stable, etc.
};

/**
 * @brief Mitigation strategy for a CWE
 */
struct Mitigation {
    std::string phase;              // Implementation, Architecture, Build, etc.
    std::string strategy;           // Input Validation, Output Encoding, etc.
    std::string description;        // Detailed mitigation description
    std::string effectiveness;      // High, Moderate, Limited, Unknown
};

/**
 * @brief Code example for a CWE
 */
struct CweExample {
    std::string language;           // C, C++, Java, etc.
    std::string example_type;       // Vulnerable, Safe, Attack
    std::string code;               // Code snippet
    std::string description;        // Description of the example
};

/**
 * @brief CWE relationship
 */
struct CweRelationship {
    std::string target_cwe_id;      // Related CWE ID
    std::string relationship_type;  // ChildOf, ParentOf, etc.
};

/**
 * @brief Repository for accessing CWE database
 *
 * Provides methods to:
 * - Query CWE information
 * - Get mitigations
 * - Navigate CWE relationships
 * - Map vulnerability IDs to CWEs
 */
class CweRepository {
public:
    /**
     * @brief Construct a CWE repository
     * @param database_path Path to SQLite database file
     * @throws std::runtime_error if database cannot be opened
     */
    explicit CweRepository(const std::string& database_path);

    /**
     * @brief Destructor
     */
    ~CweRepository();

    // Disable copy (SQLite connection is not copyable)
    CweRepository(const CweRepository&) = delete;
    CweRepository& operator=(const CweRepository&) = delete;

    // Allow move
    CweRepository(CweRepository&&) noexcept;
    CweRepository& operator=(CweRepository&&) noexcept;

    /**
     * @brief Get CWE information by ID
     * @param cwe_id CWE ID (e.g., "CWE-120" or "120")
     * @return CWE info if found, std::nullopt otherwise
     */
    std::optional<CweInfo> get_cwe_info(const std::string& cwe_id) const;

    /**
     * @brief Get CWE information by number
     * @param cwe_number CWE number (e.g., 120)
     * @return CWE info if found, std::nullopt otherwise
     */
    std::optional<CweInfo> get_cwe_info(int cwe_number) const;

    /**
     * @brief Get mitigations for a CWE
     * @param cwe_id CWE ID
     * @return Vector of mitigations (empty if none found)
     */
    std::vector<Mitigation> get_mitigations(const std::string& cwe_id) const;

    /**
     * @brief Get code examples for a CWE
     * @param cwe_id CWE ID
     * @param language Optional language filter (e.g., "C", "C++")
     * @return Vector of code examples (empty if none found)
     */
    std::vector<CweExample> get_examples(const std::string& cwe_id,
                                         const std::optional<std::string>& language = std::nullopt) const;

    /**
     * @brief Get parent CWEs (more general categories)
     * @param cwe_id CWE ID
     * @return Vector of parent CWE relationships
     */
    std::vector<CweRelationship> get_parent_cwes(const std::string& cwe_id) const;

    /**
     * @brief Get child CWEs (more specific)
     * @param cwe_id CWE ID
     * @return Vector of child CWE relationships
     */
    std::vector<CweRelationship> get_child_cwes(const std::string& cwe_id) const;

    /**
     * @brief Get all CWE relationships for a given CWE
     * @param cwe_id CWE ID
     * @return Vector of all relationships
     */
    std::vector<CweRelationship> get_relationships(const std::string& cwe_id) const;

    /**
     * @brief Map vulnerability ID to CWE
     * @param vuln_id Vulnerability ID (e.g., "SRC_UNSAFE_CALL_gets")
     * @return CWE ID if mapping exists, std::nullopt otherwise
     */
    std::optional<std::string> map_vuln_to_cwe(const std::string& vuln_id) const;

    /**
     * @brief Add or update vulnerability-to-CWE mapping
     * @param vuln_id Vulnerability ID
     * @param cwe_id CWE ID
     * @param confidence Confidence level (0-100)
     * @param notes Optional notes
     * @return true if successful, false otherwise
     */
    bool add_vuln_mapping(const std::string& vuln_id,
                         const std::string& cwe_id,
                         int confidence = 100,
                         const std::string& notes = "");

    /**
     * @brief Check if database is open and ready
     * @return true if database is ready, false otherwise
     */
    bool is_ready() const;

    /**
     * @brief Get database path
     * @return Path to database file
     */
    std::string get_database_path() const;

    /**
     * @brief Initialize database with schema
     *
     * Creates tables and initializes with sample data if database is empty.
     * Should be called once when creating a new database.
     *
     * @param schema_sql_path Path to schema SQL file
     * @return true if successful, false otherwise
     */
    bool initialize_database(const std::string& schema_sql_path);

    /**
     * @brief Get count of CWE entries in database
     * @return Number of CWE entries
     */
    int get_cwe_count() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sentinelx
