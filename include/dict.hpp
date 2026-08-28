#pragma once

#include <memory>
#include <cstring>
#include <iostream>
#include <exception>
#include <unordered_map>
#include "configs.hpp"
#include "crypt.hpp"

struct SafeVarHash {
    private:
        crypto::SafeVar pepper;
        bool is_init = false;

    public:
        SafeVarHash() = default;

        SafeVarHash(crypto::SafeVar &session_key) :pepper(session_key), is_init(true) { pepper.short_hash_pepper_gen("HashMap"); }

        size_t operator()(const crypto::SafeVar& obj) const {
            if (!is_init) throw std::runtime_error("Attempt to hash on an uninitialized dictionary hash map.");
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

        void init(crypto::SafeVar &session_key, size_t init_buckets) { Base::operator=(Base(init_buckets, SafeVarHash(session_key))); }

        void clear() { Base::operator=(Base()); }

        crypto::SafeVar pack(crypto::SafeVar &session_key, crypto::SafeVar &master_key);
};