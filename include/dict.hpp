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

    public:
        SafeVarHash() = default;

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

class Dict {
    private:
        using Map = std::unordered_map<crypto::SafeVar, crypto::SafeVar, SafeVarHash, SafeVarEq>;

        crypto::SafeVar session_key;
        Map map;

    public:
        Dict(crypto::SafeVar data) : session_key(crypto::key_len, true), map(1.5 * data.get_size()/config::slot_len, SafeVarHash(session_key)) { load(std::move(data)); }

        bool contains(const crypto::SafeVar &name) const { return map.contains(name); }

        auto erase(Map::iterator it) { return map.erase(it); }

        auto extract(crypto::SafeVar& node) { return map.extract(node); }

        auto insert(Map::node_type &&node) { return map.insert(std::move(node)); }

        auto begin() { return map.begin(); }
        auto end() { return map.end(); }
        auto size() { return map.size(); }
        auto empty() { return map.empty(); }

        std::pair<Dict::Map::iterator, bool> emplace(crypto::SafeVar &&name, crypto::SafeVar &&password);

        std::pair<Dict::Map::iterator, bool> insert_or_assign(crypto::SafeVar &name, crypto::SafeVar &&password);

        crypto::SafeVar change_password(crypto::SafeVar &name, crypto::SafeVar &&password);

        void restore_password(crypto::SafeVar &name, crypto::SafeVar &&password);

        Dict::Map::iterator change_name(crypto::SafeVar &name, crypto::SafeVar &&new_name);

        crypto::SafeVar get_password(crypto::SafeVar &name);

        crypto::SafeVar pack() const;

        void load(crypto::SafeVar data);
};