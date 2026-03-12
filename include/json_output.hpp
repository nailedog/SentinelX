#pragma once
#include <iosfwd>
#include "report.hpp"

namespace sx {

void print_json(const AnalysisReport& report, std::ostream& os);

}
