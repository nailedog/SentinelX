#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace sentinel {

struct Token {
    std::string text;
    std::size_t column = 0;
};

std::vector<Token> tokenize(const std::string& line);

class SimpleFSM {
public:
    enum class State {
        Start,
        Identifier,
        Number,
        StringLiteral,
        CharLiteral,
        CommentLine,
        CommentBlock
    };

    using TransitionCallback =
        std::function<void(State prev, State curr, char ch, std::size_t index)>;

    explicit SimpleFSM(TransitionCallback cb = {});
    void reset();
    void process(const std::string& line);

private:
    State state_;
    TransitionCallback callback_;
};

} 
