#pragma once

#include <memory>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include "configs.hpp"
#include "crypt.hpp"

struct SafeVarHash {
    private:
        crypto::SafeVar pepper;

    public:
        SafeVarHash(crypto::SafeVar &session_key) :pepper(session_key) { pepper.short_hash_pepper_gen("HashMap"); }

        size_t operator()(const crypto::SafeVar& obj) const {
            return obj.short_hash(pepper, std::strlen((const char *)obj.get())); 
        }
};

struct SafeVarEq {
    bool operator()(const crypto::SafeVar &lhs, const crypto::SafeVar &rhs) const noexcept {
        return !std::strcmp((const char *)lhs.get(), (const char *)rhs.get());
    }
};

class Dict final : private std::unordered_map<crypto::SafeVar, crypto::SafeVar, SafeVarHash, SafeVarEq> {
private:
    static constexpr int init_buckets = 10; // based this on the size of the file
    crypto::SafeVar &session_key;
    using Base = std::unordered_map<crypto::SafeVar, crypto::SafeVar, SafeVarHash, SafeVarEq>;

public:
    // expose to public (we do not inherit public since std::unordered_map has no virtual destructor)
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

    Dict(crypto::SafeVar &_session_key) : Base(init_buckets, SafeVarHash(_session_key)), session_key(_session_key) {}

    void init() { Base::operator=(Base(init_buckets, SafeVarHash(session_key))); }

    void clear() {
        crypto::SafeVar temp(crypto::key_len);
        Base::operator=(Base(0, SafeVarHash(temp)));
    }

    crypto::SafeVar pack(crypto::SafeVar &session_key, crypto::SafeVar &master_key);
};