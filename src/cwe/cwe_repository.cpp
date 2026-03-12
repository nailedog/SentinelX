#include "../../include/sentinelx/cwe/cwe_repository.h"
#include <sqlite3.h>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <iostream>

namespace sentinelx {

// =============================================================================
// CweRepository::Impl - Private implementation (Pimpl idiom)
// =============================================================================
class CweRepository::Impl {
public:
    sqlite3* db = nullptr;
    std::string db_path;

    explicit Impl(const std::string& database_path) : db_path(database_path) {
        int rc = sqlite3_open(database_path.c_str(), &db);
        if (rc != SQLITE_OK) {
            std::string error = sqlite3_errmsg(db);
            sqlite3_close(db);
            throw std::runtime_error("Failed to open CWE database: " + error);
        }
    }

    ~Impl() {
        if (db) {
            sqlite3_close(db);
        }
    }

    // Helper to execute a query and call callback for each row
    template<typename Callback>
    bool execute_query(const std::string& sql, Callback callback) const {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);

        if (rc != SQLITE_OK) {
            std::cerr << "SQL prepare error: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            callback(stmt);
        }

        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    }

    // Helper to get string from column
    static std::string get_text(sqlite3_stmt* stmt, int col) {
        const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, col));
        return text ? std::string(text) : "";
    }

    // Helper to get int from column
    static int get_int(sqlite3_stmt* stmt, int col) {
        return sqlite3_column_int(stmt, col);
    }
};

// =============================================================================
// CweRepository Implementation
// =============================================================================

CweRepository::CweRepository(const std::string& database_path)
    : impl_(std::make_unique<Impl>(database_path)) {
}

CweRepository::~CweRepository() = default;

CweRepository::CweRepository(CweRepository&&) noexcept = default;
CweRepository& CweRepository::operator=(CweRepository&&) noexcept = default;

std::optional<CweInfo> CweRepository::get_cwe_info(const std::string& cwe_id) const {
    // Normalize CWE ID (accept both "CWE-120" and "120")
    std::string normalized_id = cwe_id;
    if (normalized_id.find("CWE-") != 0) {
        normalized_id = "CWE-" + cwe_id;
    }

    const std::string sql =
        "SELECT cwe_id, cwe_number, name, description, extended_description, "
        "severity, likelihood, abstraction, structure, status "
        "FROM cwe_entries WHERE cwe_id = ?";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, normalized_id.c_str(), -1, SQLITE_STATIC);

    std::optional<CweInfo> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CweInfo info;
        info.cwe_id = Impl::get_text(stmt, 0);
        info.cwe_number = Impl::get_int(stmt, 1);
        info.name = Impl::get_text(stmt, 2);
        info.description = Impl::get_text(stmt, 3);
        info.extended_description = Impl::get_text(stmt, 4);
        info.severity = Impl::get_text(stmt, 5);
        info.likelihood = Impl::get_text(stmt, 6);
        info.abstraction = Impl::get_text(stmt, 7);
        info.structure = Impl::get_text(stmt, 8);
        info.status = Impl::get_text(stmt, 9);
        result = info;
    }

    sqlite3_finalize(stmt);
    return result;
}

std::optional<CweInfo> CweRepository::get_cwe_info(int cwe_number) const {
    return get_cwe_info("CWE-" + std::to_string(cwe_number));
}

std::vector<Mitigation> CweRepository::get_mitigations(const std::string& cwe_id) const {
    std::vector<Mitigation> mitigations;

    const std::string sql =
        "SELECT phase, strategy, description, effectiveness "
        "FROM cwe_mitigations WHERE cwe_id = ?";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return mitigations;
    }

    sqlite3_bind_text(stmt, 1, cwe_id.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Mitigation m;
        m.phase = Impl::get_text(stmt, 0);
        m.strategy = Impl::get_text(stmt, 1);
        m.description = Impl::get_text(stmt, 2);
        m.effectiveness = Impl::get_text(stmt, 3);
        mitigations.push_back(m);
    }

    sqlite3_finalize(stmt);
    return mitigations;
}

std::vector<CweExample> CweRepository::get_examples(
    const std::string& cwe_id,
    const std::optional<std::string>& language) const {

    std::vector<CweExample> examples;

    std::string sql =
        "SELECT language, example_type, code, description "
        "FROM cwe_examples WHERE cwe_id = ?";

    if (language.has_value()) {
        sql += " AND language = ?";
    }

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return examples;
    }

    sqlite3_bind_text(stmt, 1, cwe_id.c_str(), -1, SQLITE_STATIC);
    if (language.has_value()) {
        sqlite3_bind_text(stmt, 2, language->c_str(), -1, SQLITE_STATIC);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CweExample ex;
        ex.language = Impl::get_text(stmt, 0);
        ex.example_type = Impl::get_text(stmt, 1);
        ex.code = Impl::get_text(stmt, 2);
        ex.description = Impl::get_text(stmt, 3);
        examples.push_back(ex);
    }

    sqlite3_finalize(stmt);
    return examples;
}

std::vector<CweRelationship> CweRepository::get_parent_cwes(const std::string& cwe_id) const {
    std::vector<CweRelationship> relationships;

    const std::string sql =
        "SELECT target_cwe_id, relationship_type "
        "FROM cwe_relationships "
        "WHERE source_cwe_id = ? AND relationship_type LIKE '%ChildOf%'";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return relationships;
    }

    sqlite3_bind_text(stmt, 1, cwe_id.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CweRelationship rel;
        rel.target_cwe_id = Impl::get_text(stmt, 0);
        rel.relationship_type = Impl::get_text(stmt, 1);
        relationships.push_back(rel);
    }

    sqlite3_finalize(stmt);
    return relationships;
}

std::vector<CweRelationship> CweRepository::get_child_cwes(const std::string& cwe_id) const {
    std::vector<CweRelationship> relationships;

    const std::string sql =
        "SELECT source_cwe_id, relationship_type "
        "FROM cwe_relationships "
        "WHERE target_cwe_id = ? AND relationship_type LIKE '%ChildOf%'";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return relationships;
    }

    sqlite3_bind_text(stmt, 1, cwe_id.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CweRelationship rel;
        rel.target_cwe_id = Impl::get_text(stmt, 0);
        rel.relationship_type = Impl::get_text(stmt, 1);
        relationships.push_back(rel);
    }

    sqlite3_finalize(stmt);
    return relationships;
}

std::vector<CweRelationship> CweRepository::get_relationships(const std::string& cwe_id) const {
    std::vector<CweRelationship> relationships;

    const std::string sql =
        "SELECT target_cwe_id, relationship_type "
        "FROM cwe_relationships WHERE source_cwe_id = ?";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return relationships;
    }

    sqlite3_bind_text(stmt, 1, cwe_id.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CweRelationship rel;
        rel.target_cwe_id = Impl::get_text(stmt, 0);
        rel.relationship_type = Impl::get_text(stmt, 1);
        relationships.push_back(rel);
    }

    sqlite3_finalize(stmt);
    return relationships;
}

std::optional<std::string> CweRepository::map_vuln_to_cwe(const std::string& vuln_id) const {
    const std::string sql = "SELECT cwe_id FROM vuln_cwe_mapping WHERE vuln_id = ?";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, vuln_id.c_str(), -1, SQLITE_STATIC);

    std::optional<std::string> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = Impl::get_text(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return result;
}

bool CweRepository::add_vuln_mapping(
    const std::string& vuln_id,
    const std::string& cwe_id,
    int confidence,
    const std::string& notes) {

    const std::string sql =
        "INSERT OR REPLACE INTO vuln_cwe_mapping (vuln_id, cwe_id, confidence, notes) "
        "VALUES (?, ?, ?, ?)";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, vuln_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, cwe_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, confidence);
    sqlite3_bind_text(stmt, 4, notes.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

bool CweRepository::is_ready() const {
    return impl_->db != nullptr;
}

std::string CweRepository::get_database_path() const {
    return impl_->db_path;
}

bool CweRepository::initialize_database(const std::string& schema_sql_path) {
    if (!is_ready()) {
        return false;
    }

    // Read SQL file
    std::ifstream file(schema_sql_path);
    if (!file.is_open()) {
        std::cerr << "Failed to open schema file: " << schema_sql_path << std::endl;
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string sql = buffer.str();

    // Execute SQL
    char* error_msg = nullptr;
    int rc = sqlite3_exec(impl_->db, sql.c_str(), nullptr, nullptr, &error_msg);

    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << error_msg << std::endl;
        sqlite3_free(error_msg);
        return false;
    }

    return true;
}

int CweRepository::get_cwe_count() const {
    const std::string sql = "SELECT COUNT(*) FROM cwe_entries";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        return 0;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

} // namespace sentinelx
