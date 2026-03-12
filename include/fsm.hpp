#pragma once
#include <string>
#include <unordered_map>
#include <vector>

namespace sx {

enum class BufferState {
    Unknown,
    Allocated,
    Initialized,
    Tainted,    
    Sanitized,
};

struct BufferKey {
    std::string file;
    std::string function;
    std::string name;

    bool operator==(const BufferKey& other) const noexcept {
        return file == other.file
            && function == other.function
            && name == other.name;
    }
};

struct BufferKeyHash {
    std::size_t operator()(const BufferKey& k) const noexcept {
        std::hash<std::string> h;
        auto seed = h(k.file);
        seed ^= h(k.function) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h(k.name)     + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
    }
};

struct SourceLocation {
    std::string file;
    int         line = 0;
};

class BufferFSM {
public:
    void on_declare (const BufferKey& key, std::size_t size, const SourceLocation& loc);
    void on_write   (const BufferKey& key, std::size_t bytes, const SourceLocation& loc);
    void on_read    (const BufferKey& key, std::size_t bytes, const SourceLocation& loc);
    void on_sanitize(const BufferKey& key, const SourceLocation& loc);
    void on_taint   (const BufferKey& key, const SourceLocation& loc);
    void on_reset   (const BufferKey& key, const SourceLocation& loc);

    BufferState state_of(const BufferKey& key) const;

    struct BufferSnapshot {
        BufferKey      key;
        BufferState    state;
        std::size_t    size;
        SourceLocation last_loc;
    };

    std::vector<BufferSnapshot> snapshot() const;

private:
    struct BufferInfo {
        BufferState state = BufferState::Unknown;
        std::size_t size  = 0;
        std::size_t bytes_written = 0;
        SourceLocation last_loc;
    };

    std::unordered_map<BufferKey, BufferInfo, BufferKeyHash> buffers_;
};

}
