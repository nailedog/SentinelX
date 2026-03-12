#pragma once

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>

namespace sentinel {

class CallGraphAnalyzer {
public:
    CallGraphAnalyzer() = default;

    void analyze_file(const std::string& file_path);

    void add_call(const std::string& caller, const std::string& callee);

    void add_entry_point(const std::string& function_name);

    bool is_reachable(const std::string& function_name) const;

    std::unordered_set<std::string> get_reachable_functions() const;

    void clear();

private:
    void compute_reachable_functions() const;

    void dfs(const std::string& func, std::unordered_set<std::string>& visited) const;

    std::unordered_map<std::string, std::vector<std::string>> call_graph_;

    std::unordered_set<std::string> entry_points_;

    mutable std::unordered_set<std::string> reachable_functions_;

    mutable bool needs_recompute_ = true;
};

}
