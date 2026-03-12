#pragma once

#include <string>
#include <vector>

namespace sentinel {

std::string read_file(const std::string& path);
std::vector<std::string> read_lines(const std::string& path);

std::string trim(const std::string& s);

bool ends_with(const std::string& value, const std::string& suffix);
bool starts_with(const std::string& value, const std::string& prefix);

std::string to_lower(std::string s);
std::string to_upper(std::string s);

}
