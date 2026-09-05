#pragma once

#include <cstddef>
#include <string>
#include "crypt.hpp"
#include "configs.hpp"


struct Flag {
    const char *name;
    bool has_arg;
};


struct Command {
    const char *name;
    bool allow_close; // does not promise same behaviour in clsoe and open state
    bool has_arg;
    bool sudo;
    const Flag *Flags;
    const char *desc_short;
    const char *desc_long;
};

struct ShellEncoding {
    int command;
    crypto::SafeVar arg;
    unsigned char flags;
    std::vector<crypto::SafeVar> flag_args;
};

extern const Command commands[];


constexpr size_t max_command_len = []() {
    size_t max_len = 0;
    for (int i = 0; commands[i].name != nullptr; i++) {
        size_t len = std::string_view(commands[i].name).length();
        if (max_len < len) max_len = len;
    }
    return max_len;
}();


ShellEncoding parse(const char* instruction);
