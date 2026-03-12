#include "json_output.hpp"
#include <cstdio>
#include <string>
#include <iostream>

namespace sx {

namespace {
std::string escape_json(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
        case '\"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c & 0xff);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}
} 

void print_json(const AnalysisReport& report, std::ostream& os) {
    os << "{\n";
    os << "  \"files_analyzed\": " << report.files_analyzed << ",\n";
    os << "  \"issues_found\": " << (report.has_issues() ? "true" : "false") << ",\n";
    os << "  \"findings\": [\n";

    for (std::size_t i = 0; i < report.findings.size(); ++i) {
        const auto& f = report.findings[i];
        os << "    {\n";
        os << "      \"file\": \""       << escape_json(f.file)       << "\",\n";
        os << "      \"line\": "        << f.line                    << ",\n";
        os << "      \"function\": \""  << escape_json(f.function)   << "\",\n";
        os << "      \"buffer\": \""    << escape_json(f.buffer)     << "\",\n";
        os << "      \"kind\": \""      << escape_json(f.kind)       << "\",\n";
        os << "      \"severity\": \""  << escape_json(f.severity)   << "\",\n";
        os << "      \"confidence\": \"" << escape_json(f.confidence) << "\",\n";
        os << "      \"message\": \""   << escape_json(f.message)    << "\",\n";
        os << "      \"return_address\": \"" << escape_json(f.return_address) << "\"\n";
        os << "    }" << (i + 1 < report.findings.size() ? "," : "") << "\n";
    }

    os << "  ]\n";
    os << "}\n";
}

}
