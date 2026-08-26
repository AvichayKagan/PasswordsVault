#pragma once

#include <memory>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include "configs.hpp"
#include "crypt.hpp"

struct SafeVarHash {
    private:
        crypto::SafeVar &salt;

    public:
        SafeVarHash(crypto::SafeVar &_salt) :salt(_salt) {}

        std::size_t operator()(const crypto::SafeVar& obj) const; // must not except
};

class Dict final : public std::unordered_map<crypto::SafeVar, crypto::SafeVar, SafeVarHash> {
private:
    using Base = std::unordered_map<crypto::SafeVar, crypto::SafeVar, SafeVarHash>;
public:

    Dict(crypto::SafeVar &session_key) : Base(0, SafeVarHash(session_key)) {}

    crypto::SafeVar pack(crypto::SafeVar &session_key, crypto::SafeVar &master_key);

    void list_keys() {
        for (const auto& i : *this) std::cout << i.first.get() << '\n';
        std::cout << std::endl;
    }
};