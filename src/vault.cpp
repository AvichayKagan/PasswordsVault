#include <iostream>
#include "vault.hpp"
#include "safe_io.hpp"

namespace vault {

crypto::SafeVar Vault::get_master_key(crypto::SafeVar &&master_password) {
    crypto::SafeVar hash = std::move(master_password);
    crypto::SafeVar master_key = master_key_enc;
    hash.hash(salt);

    try {
        master_key.decrypto(hash.get(), true);
    }
    catch (const crypto::Error& e) {
        if (e.code() == crypto::IncorrectPassword) return crypto::SafeVar();
        throw;
    }

    return master_key;
}


void Vault::flush(crypto::SafeVar master_key) {
    crypto::SafeVar data = dictionary->pack();
    data.encrypto(master_key.get());
    master_key.memzero();

    disk_mang.atomic_write_file(master_key_enc, salt, data);
}


bool Vault::open_vault(crypto::SafeVar &&master_password) {
    crypto::SafeVar master_key = get_master_key(std::move(master_password));
    if (master_key.get() == nullptr) return false;

    // read disk
    crypto::SafeVar data = disk_mang.read_vault_data();

    data.decrypto(master_key.get(), false);
    master_key.memzero();

    dictionary = DictPtr(std::move(data));

    return true;
}


void Vault::init_vault(crypto::SafeVar &&master_password) {
    master_key_enc.random();
    crypto::random(salt, crypto::salt_len);
    
    crypto::SafeVar password_hash = master_password;
    password_hash.hash(salt);
    
    master_key_enc.encrypto(password_hash.get());

    dictionary = DictPtr(crypto::SafeVar(0)); // inlined open_vault for the case of empty vault that bypass the read/write chicken and egg issue

    flush(std::move(master_password));
}


bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_password) {
    crypto::SafeVar master_key = get_master_key(std::move(master_password));
    if (master_key.get() == nullptr) return false;

    if (dictionary->contains(name)) return true; // if name exists if does not cahnge the password!
    
    auto name_it = dictionary->emplace(std::move(name), std::move(password)).first; // the change to revert in case of exception

    try {
        flush(std::move(master_key));
    }
    catch (...) {
        dictionary->erase(name_it);
        throw;
    }

    return true;
}


bool Vault::del_password(crypto::SafeVar &name, crypto::SafeVar &&master_password) {
    crypto::SafeVar master_key = get_master_key(std::move(master_password));
    if (master_key.get() == nullptr) return false;

    if (!dictionary->contains(name)) return true;

    auto node = dictionary->extract(name); // the change to revert in case of exception

    try {
        flush(std::move(master_key));
    }
    catch (...) {
        dictionary->insert(std::move(node)); // noexcept?
        throw;
    }
     
    return true;
}

bool Vault::change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_password) {
    crypto::SafeVar master_key = get_master_key(std::move(master_password));
    if (master_key.get() == nullptr) return false;

    crypto::SafeVar old_password = dictionary->change_password(name, std::move(password));

    try {
        flush(std::move(master_key));
    }
    catch (...) {
        dictionary->change_password(name, std::move(old_password));
        throw;
    }
     
    return true;
}


bool Vault::change_name(crypto::SafeVar &&name, crypto::SafeVar &new_name, crypto::SafeVar &&master_password) {
    crypto::SafeVar master_key = get_master_key(std::move(master_password));
    if (master_key.get() == nullptr) return false;

    dictionary->change_name(name, crypto::SafeVar(new_name));

    try {
        flush(std::move(master_key));
    }
    catch (...) {
        dictionary->change_name(new_name, std::move(name));
        throw;
    }
    
    return true;
}


bool Vault::change_master(crypto::SafeVar &&new_master, crypto::SafeVar &&master_password) {
    crypto::SafeVar master_key = get_master_key(std::move(master_password));
    if (master_key.get() == nullptr) return false;

    // encyrpt the new master
    crypto::SafeVar new_hash = std::move(new_master);
    new_hash.hash(salt);
    crypto::SafeVar new_master_enc = master_key;
    new_master_enc.encrypto(new_hash.get());

    crypto::SafeVar old_master_key_enc = std::move(master_key_enc); // the point of revert, no except
    master_key_enc = std::move(new_master_enc); // no except

    try {
        flush(std::move(master_key));
    }
    catch (...) {
        master_key_enc = std::move(old_master_key_enc);
        throw;
    }

    return true;
}


// this does not change exiting passwords
bool Vault::import_passwords(import_type batch, crypto::SafeVar &&master_password) {
    crypto::SafeVar master_key = get_master_key(std::move(master_password));
    if (master_key.get() == nullptr) return false;
    
    for (int i = 0; batch[i].first.get() != nullptr; i++) {
        auto inserted = dictionary->emplace(crypto::SafeVar(batch[i].first), crypto::SafeVar(batch[i].second)).second;
        if (!inserted) {
            batch[i].second = crypto::SafeVar();
        }
    }

    try {
        flush(std::move(master_key));
    }
    catch (...) {
        for (int i = 0; batch[i].first.get() != nullptr; i++) {
            if (batch[i].second.get() != nullptr) dictionary->extract(batch[i].first);
        }
        throw;
    }

    return true;
}


} // namespace vault