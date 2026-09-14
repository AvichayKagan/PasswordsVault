#pragma once

#include <cstddef>
#include <string>
#include "crypt.hpp"
#include "configs.hpp"

namespace shell {

struct ShellEncoding {
    bool error;
    int command;
    crypto::SafeVar arg;
    unsigned char flags;
    std::vector<crypto::SafeVar> flag_args;
};


ShellEncoding parse(crypto::SafeVar &instruction);

}
