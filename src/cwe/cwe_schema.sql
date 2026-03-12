-- CWE Database Schema for SentinelX
-- Version 1.0
-- This schema stores CWE (Common Weakness Enumeration) information
-- for vulnerability classification and enrichment

-- =============================================================================
-- Main CWE Information Table
-- =============================================================================
CREATE TABLE IF NOT EXISTS cwe_entries (
    cwe_id TEXT PRIMARY KEY,                    -- e.g., "CWE-120"
    cwe_number INTEGER NOT NULL,                -- e.g., 120
    name TEXT NOT NULL,                         -- e.g., "Buffer Copy without Checking Size of Input"
    description TEXT,                           -- Full description
    extended_description TEXT,                  -- Extended technical details
    likelihood TEXT,                            -- LOW, MEDIUM, HIGH
    severity TEXT,                              -- INFO, WARNING, HIGH, CRITICAL

    -- CWE metadata
    abstraction TEXT,                           -- Base, Variant, Class, Pillar, Compound
    structure TEXT,                             -- Simple, Chain, Composite
    status TEXT,                                -- Draft, Incomplete, Stable, Deprecated

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- CWE Relationships (parent-child, peer, etc.)
-- =============================================================================
CREATE TABLE IF NOT EXISTS cwe_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_cwe_id TEXT NOT NULL,                -- Source CWE
    target_cwe_id TEXT NOT NULL,                -- Target CWE
    relationship_type TEXT NOT NULL,            -- ChildOf, ParentOf, PeerOf, CanPrecede, etc.

    FOREIGN KEY (source_cwe_id) REFERENCES cwe_entries(cwe_id) ON DELETE CASCADE,
    FOREIGN KEY (target_cwe_id) REFERENCES cwe_entries(cwe_id) ON DELETE CASCADE,
    UNIQUE(source_cwe_id, target_cwe_id, relationship_type)
);

-- =============================================================================
-- Mitigation Strategies
-- =============================================================================
CREATE TABLE IF NOT EXISTS cwe_mitigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id TEXT NOT NULL,
    phase TEXT,                                 -- Implementation, Architecture, Build, etc.
    strategy TEXT,                              -- Input Validation, Output Encoding, etc.
    description TEXT NOT NULL,
    effectiveness TEXT,                         -- High, Moderate, Limited, Unknown

    FOREIGN KEY (cwe_id) REFERENCES cwe_entries(cwe_id) ON DELETE CASCADE
);

-- =============================================================================
-- Code Examples (vulnerable and safe)
-- =============================================================================
CREATE TABLE IF NOT EXISTS cwe_examples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id TEXT NOT NULL,
    language TEXT,                              -- C, C++, Java, etc.
    example_type TEXT NOT NULL,                 -- Vulnerable, Safe, Attack
    code TEXT NOT NULL,
    description TEXT,

    FOREIGN KEY (cwe_id) REFERENCES cwe_entries(cwe_id) ON DELETE CASCADE
);

-- =============================================================================
-- Platform/Language-Specific Applicability
-- =============================================================================
CREATE TABLE IF NOT EXISTS cwe_applicability (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id TEXT NOT NULL,
    language TEXT,                              -- C, C++, Java, Python, etc.
    platform TEXT,                              -- Windows, Linux, macOS, etc.
    technology TEXT,                            -- Web, Mobile, Desktop, Embedded

    FOREIGN KEY (cwe_id) REFERENCES cwe_entries(cwe_id) ON DELETE CASCADE
);

-- =============================================================================
-- Detection Methods
-- =============================================================================
CREATE TABLE IF NOT EXISTS cwe_detection_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id TEXT NOT NULL,
    method TEXT NOT NULL,                       -- Automated Static Analysis, Manual Review, etc.
    effectiveness TEXT,                         -- High, Moderate, Limited
    description TEXT,

    FOREIGN KEY (cwe_id) REFERENCES cwe_entries(cwe_id) ON DELETE CASCADE
);

-- =============================================================================
-- References (papers, websites, standards)
-- =============================================================================
CREATE TABLE IF NOT EXISTS cwe_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id TEXT NOT NULL,
    reference_type TEXT,                        -- CVE, Paper, Website, Standard
    reference_id TEXT,                          -- CVE-2023-1234, CWE-120, etc.
    title TEXT,
    url TEXT,

    FOREIGN KEY (cwe_id) REFERENCES cwe_entries(cwe_id) ON DELETE CASCADE
);

-- =============================================================================
-- SentinelX Vulnerability ID to CWE Mapping
-- =============================================================================
CREATE TABLE IF NOT EXISTS vuln_cwe_mapping (
    vuln_id TEXT PRIMARY KEY,                   -- e.g., "SRC_UNSAFE_CALL_gets"
    cwe_id TEXT NOT NULL,                       -- e.g., "CWE-120"
    confidence INTEGER DEFAULT 100,             -- 0-100, how confident is this mapping
    notes TEXT,                                 -- Additional context

    FOREIGN KEY (cwe_id) REFERENCES cwe_entries(cwe_id) ON DELETE CASCADE
);

-- =============================================================================
-- Indexes for Performance
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_cwe_number ON cwe_entries(cwe_number);
CREATE INDEX IF NOT EXISTS idx_cwe_severity ON cwe_entries(severity);
CREATE INDEX IF NOT EXISTS idx_cwe_status ON cwe_entries(status);
CREATE INDEX IF NOT EXISTS idx_relationship_source ON cwe_relationships(source_cwe_id);
CREATE INDEX IF NOT EXISTS idx_relationship_target ON cwe_relationships(target_cwe_id);
CREATE INDEX IF NOT EXISTS idx_relationship_type ON cwe_relationships(relationship_type);
CREATE INDEX IF NOT EXISTS idx_mitigation_cwe ON cwe_mitigations(cwe_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_phase ON cwe_mitigations(phase);
CREATE INDEX IF NOT EXISTS idx_example_cwe ON cwe_examples(cwe_id);
CREATE INDEX IF NOT EXISTS idx_example_language ON cwe_examples(language);
CREATE INDEX IF NOT EXISTS idx_applicability_cwe ON cwe_applicability(cwe_id);
CREATE INDEX IF NOT EXISTS idx_detection_cwe ON cwe_detection_methods(cwe_id);
CREATE INDEX IF NOT EXISTS idx_reference_cwe ON cwe_references(cwe_id);
CREATE INDEX IF NOT EXISTS idx_vuln_mapping_cwe ON vuln_cwe_mapping(cwe_id);

-- =============================================================================
-- Initial Sample Data (Top CWEs for Testing)
-- =============================================================================

-- CWE-120: Buffer Copy without Checking Size of Input
INSERT OR IGNORE INTO cwe_entries (cwe_id, cwe_number, name, description, likelihood, severity, abstraction, status) VALUES
('CWE-120', 120, 'Buffer Copy without Checking Size of Input',
 'The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer, leading to a buffer overflow.',
 'HIGH', 'CRITICAL', 'Base', 'Stable');

-- CWE-787: Out-of-bounds Write
INSERT OR IGNORE INTO cwe_entries (cwe_id, cwe_number, name, description, likelihood, severity, abstraction, status) VALUES
('CWE-787', 787, 'Out-of-bounds Write',
 'The product writes data past the end, or before the beginning, of the intended buffer.',
 'HIGH', 'CRITICAL', 'Base', 'Stable');

-- CWE-134: Use of Externally-Controlled Format String
INSERT OR IGNORE INTO cwe_entries (cwe_id, cwe_number, name, description, likelihood, severity, abstraction, status) VALUES
('CWE-134', 134, 'Use of Externally-Controlled Format String',
 'The product uses a function that accepts a format string as an argument, but the format string originates from an external source.',
 'MEDIUM', 'HIGH', 'Base', 'Stable');

-- CWE-78: OS Command Injection
INSERT OR IGNORE INTO cwe_entries (cwe_id, cwe_number, name, description, likelihood, severity, abstraction, status) VALUES
('CWE-78', 78, 'OS Command Injection',
 'The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.',
 'MEDIUM', 'HIGH', 'Base', 'Stable');

-- CWE-190: Integer Overflow or Wraparound
INSERT OR IGNORE INTO cwe_entries (cwe_id, cwe_number, name, description, likelihood, severity, abstraction, status) VALUES
('CWE-190', 190, 'Integer Overflow or Wraparound',
 'The product performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value.',
 'MEDIUM', 'HIGH', 'Base', 'Stable');

-- CWE-676: Use of Potentially Dangerous Function
INSERT OR IGNORE INTO cwe_entries (cwe_id, cwe_number, name, description, likelihood, severity, abstraction, status) VALUES
('CWE-676', 676, 'Use of Potentially Dangerous Function',
 'The product invokes a potentially dangerous function that could introduce a vulnerability if it is used incorrectly, but the function can also be used safely.',
 'MEDIUM', 'HIGH', 'Base', 'Stable');

-- CWE-131: Incorrect Calculation of Buffer Size
INSERT OR IGNORE INTO cwe_entries (cwe_id, cwe_number, name, description, likelihood, severity, abstraction, status) VALUES
('CWE-131', 131, 'Incorrect Calculation of Buffer Size',
 'The product does not correctly calculate the size to be used when allocating a buffer, which could lead to a buffer overflow.',
 'MEDIUM', 'HIGH', 'Variant', 'Stable');

-- CWE-121: Stack-based Buffer Overflow
INSERT OR IGNORE INTO cwe_entries (cwe_id, cwe_number, name, description, likelihood, severity, abstraction, status) VALUES
('CWE-121', 121, 'Stack-based Buffer Overflow',
 'A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack.',
 'HIGH', 'CRITICAL', 'Variant', 'Stable');

-- CWE-789: Memory Allocation with Excessive Size Value
INSERT OR IGNORE INTO cwe_entries (cwe_id, cwe_number, name, description, likelihood, severity, abstraction, status) VALUES
('CWE-789', 789, 'Memory Allocation with Excessive Size Value',
 'The product allocates memory based on an untrusted, large size value, but it does not validate or incorrectly validates the size, allowing arbitrary amounts of memory to be allocated.',
 'MEDIUM', 'CRITICAL', 'Base', 'Stable');

-- =============================================================================
-- Sample Vulnerability ID to CWE Mappings
-- =============================================================================
INSERT OR IGNORE INTO vuln_cwe_mapping (vuln_id, cwe_id, confidence, notes) VALUES
('SRC_UNSAFE_CALL_gets', 'CWE-120', 100, 'gets() always vulnerable to buffer overflow'),
('SRC_UNSAFE_CALL_strcpy', 'CWE-120', 100, 'strcpy() without bounds checking'),
('SRC_UNSAFE_CALL_strcat', 'CWE-120', 100, 'strcat() without bounds checking'),
('SRC_UNSAFE_CALL_sprintf', 'CWE-120', 95, 'sprintf() can overflow if not used carefully'),
('SRC_FORMAT_STRING_VULN', 'CWE-134', 100, 'Format string vulnerability'),
('SRC_COMMAND_INJECTION', 'CWE-78', 100, 'OS command injection'),
('SRC_INTEGER_OVERFLOW_atoi', 'CWE-190', 90, 'Integer overflow in atoi()'),
('SRC_ARITHMETIC_OVERFLOW', 'CWE-190', 85, 'Arithmetic overflow'),
('SRC_BUFFER_OVERFLOW_MEMCPY', 'CWE-120', 90, 'memcpy() buffer overflow'),
('SRC_BUFFER_OVERFLOW_READ', 'CWE-787', 85, 'Out-of-bounds read'),
('SRC_LARGE_STACK_BUFFER', 'CWE-121', 70, 'Large stack buffer allocation'),
('SRC_ALLOCATION_OVERFLOW', 'CWE-789', 90, 'Memory allocation with untrusted size'),
('BIN_UNSAFE_CALL_gets', 'CWE-120', 100, 'gets() call in binary'),
('BIN_UNSAFE_CALL_strcpy', 'CWE-120', 100, 'strcpy() call in binary');

-- =============================================================================
-- Sample Mitigations
-- =============================================================================
INSERT OR IGNORE INTO cwe_mitigations (cwe_id, phase, strategy, description, effectiveness) VALUES
('CWE-120', 'Implementation', 'Input Validation',
 'Use bounded string functions like strncpy(), strlcpy(), or snprintf() instead of unbounded functions like strcpy(), strcat(), or gets().',
 'High'),

('CWE-120', 'Implementation', 'Library',
 'Use safer C++ string classes (std::string) instead of C-style character arrays.',
 'High'),

('CWE-134', 'Implementation', 'Output Encoding',
 'Always use constant format strings. If dynamic format strings are needed, sanitize user input thoroughly and use %s instead of direct string interpolation.',
 'High'),

('CWE-134', 'Implementation', 'Input Validation',
 'Validate and sanitize all user input before using it in format string functions.',
 'Moderate'),

('CWE-78', 'Implementation', 'Input Validation',
 'Use allowlists to validate command arguments. Avoid constructing OS commands from user input when possible.',
 'High'),

('CWE-78', 'Architecture', 'Separation of Privilege',
 'Use language features or libraries that avoid direct system command execution. For example, use built-in functions instead of system() calls.',
 'High'),

('CWE-190', 'Implementation', 'Input Validation',
 'Ensure that all integer operations are checked for overflow before use in calculations or allocations.',
 'High'),

('CWE-190', 'Implementation', 'Library',
 'Use safe integer arithmetic libraries that detect overflows.',
 'Moderate'),

('CWE-676', 'Implementation', 'Library',
 'Replace dangerous functions with safer alternatives (e.g., gets() → fgets(), sprintf() → snprintf()).',
 'High');

-- =============================================================================
-- Sample CWE Relationships
-- =============================================================================
INSERT OR IGNORE INTO cwe_relationships (source_cwe_id, target_cwe_id, relationship_type) VALUES
('CWE-121', 'CWE-787', 'ChildOf'),     -- Stack-based buffer overflow is a type of out-of-bounds write
('CWE-120', 'CWE-787', 'ChildOf'),     -- Buffer copy without checking is a type of out-of-bounds write
('CWE-131', 'CWE-120', 'CanPrecede'),  -- Incorrect buffer size calculation can lead to buffer overflow
('CWE-789', 'CWE-190', 'CanPrecede');  -- Excessive allocation can be caused by integer overflow

-- =============================================================================
-- Sample Applicability
-- =============================================================================
INSERT OR IGNORE INTO cwe_applicability (cwe_id, language, platform, technology) VALUES
('CWE-120', 'C', NULL, NULL),
('CWE-120', 'C++', NULL, NULL),
('CWE-787', 'C', NULL, NULL),
('CWE-787', 'C++', NULL, NULL),
('CWE-134', 'C', NULL, NULL),
('CWE-134', 'C++', NULL, NULL),
('CWE-78', NULL, 'Linux', NULL),
('CWE-78', NULL, 'Windows', NULL),
('CWE-78', NULL, 'macOS', NULL),
('CWE-190', 'C', NULL, NULL),
('CWE-190', 'C++', NULL, NULL);

-- =============================================================================
-- Sample Detection Methods
-- =============================================================================
INSERT OR IGNORE INTO cwe_detection_methods (cwe_id, method, effectiveness, description) VALUES
('CWE-120', 'Automated Static Analysis', 'High',
 'Static analysis tools can detect many instances of unsafe buffer operations by analyzing data flow and function calls.'),

('CWE-134', 'Automated Static Analysis', 'High',
 'Format string vulnerabilities are relatively easy to detect through static analysis by identifying non-constant format strings.'),

('CWE-78', 'Automated Static Analysis', 'Moderate',
 'Static analysis can detect command injection patterns, but may have false positives and negatives.'),

('CWE-190', 'Automated Static Analysis', 'Moderate',
 'Integer overflow detection requires sophisticated data flow analysis and may produce false positives.');

-- =============================================================================
-- End of Schema
-- =============================================================================
