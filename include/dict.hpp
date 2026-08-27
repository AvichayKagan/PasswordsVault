#pragma once

#include <memory>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include "configs.hpp"
#include "crypt.hpp"

struct SafeVarHash {
    private:
        crypto::SafeVar &pepper;

    public:
        SafeVarHash(crypto::SafeVar &_pepper) :pepper(_pepper) {}

        std::size_t operator()(const crypto::SafeVar& obj) const; // must not except
};

struct SafeVarEq {
    bool operator()(const crypto::SafeVar &lhs, const crypto::SafeVar &rhs) const noexcept {
        return !std::strcmp((char *)lhs.get(), (char *)rhs.get());
    }
};

class Dict final : private std::unordered_map<crypto::SafeVar, crypto::SafeVar, SafeVarHash, SafeVarEq> {
private:
    static constexpr int init_buckets = 10;

    using Base = std::unordered_map<crypto::SafeVar, crypto::SafeVar, SafeVarHash, SafeVarEq>;
public:
    // expose to public (we do not inherit public since std::unordered_map has no virtual destructor)
    using Base::clear;
    using Base::contains;
    using Base::find;
    using Base::insert;
    using Base::erase;
    using Base::end;
    using Base::begin;
    using Base::empty;
    using Base::size;
    using Base::emplace;
    using Base::extract;

    Dict(crypto::SafeVar &session_key) : Base(init_buckets, SafeVarHash(session_key)) {}

    crypto::SafeVar pack(crypto::SafeVar &session_key, crypto::SafeVar &master_key);
};