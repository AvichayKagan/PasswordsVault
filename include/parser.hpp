#pragma once

#include <cstddef>
#include <string>
#include "crypt.hpp"
#include "configs.hpp"



struct ShellEncoding {
    int command;
    crypto::SafeVar arg;
    unsigned char flags;
    std::vector<crypto::SafeVar> flag_args;
};


ShellEncoding parse(crypto::SafeVar &instruction);
