#include <iostream>
#include "vault.hpp"
#include "safe_io.hpp"

namespace vault {


bool Vault::flush(crypto::SafeVar master_password) {
    crypto::SafeVar master_key = master_key_enc;
    master_password.hash(salt);

    try {
        master_key.decrypto(master_password.get(), true);
    }
    catch (const crypto::Error& e) {
        if (e.code() == crypto::IncorrectPassword) return false;
        throw;
    }

    crypto::SafeVar data = dictionary->pack();
    data.encrypto(master_key.get());
    master_password.memzero();
    master_key.memzero();

    disk_mang.atomic_write_file(master_key_enc, salt, data);

    return true;
}


bool Vault::open_vault(crypto::SafeVar master_password) {
    // read disk
    crypto::SafeVar data = disk_mang.read_vault_data();

    master_password.hash(salt);
    crypto::SafeVar master_key = master_key_enc;
    try {
        master_key.decrypto(master_password.get(), true);
    }
    catch (const crypto::Error& e) {
        if (e.code() == crypto::IncorrectPassword) return false;
        throw;
    }
    data.decrypto(master_key.get(), false);
    master_password.memzero();
    master_key.memzero();

    dictionary = std::make_unique<Dict>(std::move(data));

    return true;
}


void Vault::init_vault(crypto::SafeVar &&master_passowrd) {
    crypto::SafeVar password_hash;
    crypto::SafeVar data;

    master_key_enc.random();
    crypto::random(salt, crypto::salt_len);
    
    password_hash = master_passowrd;
    password_hash.hash(salt);
    
    master_key_enc.encrypto(password_hash.get());
    password_hash.memzero();

    dictionary = std::make_unique<Dict>(crypto::SafeVar(0)); // inlined open_vault for the case of empty vault that bypass the read/write chicken and egg issue

    flush(std::move(master_passowrd));
}


bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_password) {
    if (dictionary->contains(name)) return true;
    
    auto name_it = dictionary->emplace(std::move(name), std::move(password)).first; // the change to revert in case of exception

    if (master_password.get() != nullptr) {
        try {
            if (!flush(std::move(master_password))) {
                dictionary->erase(name_it);
                return false;
            }
        }
        catch (...) {
            dictionary->erase(name_it);
            throw;
        }
    }

    return true;
}


bool Vault::del_password(crypto::SafeVar &name, crypto::SafeVar &&master_password) {
    if (!dictionary->contains(name)) return true;

    auto node = dictionary->extract(name); // the change to revert in case of exception

    if (master_password.get() != nullptr) {
        try {
            if (!flush(std::move(master_password))) {
                dictionary->insert(std::move(node));
                return false;
            }
        }
        catch (...) {
            dictionary->insert(std::move(node)); // noexcept?
            throw;
        }
    }
     
    return true;
}

bool Vault::change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_password) {
    crypto::SafeVar old_password = dictionary->change_password(name, std::move(password));

    if (master_password.get() != nullptr) {
        try {
            if (!flush(std::move(master_password))) {
                dictionary->change_password(name, std::move(old_password));
                return false;
            }
        }
        catch (...) {
            dictionary->restore_password(name, std::move(old_password));
            throw;
        }
    }
     
    return true;
}


bool Vault::change_name(crypto::SafeVar &&name, crypto::SafeVar &new_name, crypto::SafeVar &&master_password) {
    dictionary->change_name(name, crypto::SafeVar(new_name));

    if (master_password.get() != nullptr) {
        try {
            if (!flush(std::move(master_password))) {
                dictionary->change_name(new_name, std::move(name));
                return false;
            }
        }
        catch (...) {
            dictionary->change_name(new_name, std::move(name));
            throw;
        }
    }
    
    return true;
}


bool Vault::change_master(crypto::SafeVar &&new_master, crypto::SafeVar &&master_password) {
    crypto::SafeVar master_key = master_key_enc;
    crypto::SafeVar password_hash = std::move(master_password);
    password_hash.hash(salt);
    try {
        master_key.decrypto(password_hash.get(), true);
    }
    catch (const crypto::Error& e) {
        if (e.code() == crypto::IncorrectPassword) return false;
        throw;
    }
    

    crypto::SafeVar new_hash = new_master;
    new_hash.hash(salt);
    master_key.encrypto(new_hash.get());
    crypto::SafeVar old_master_key_enc = std::move(master_key_enc); // the point of revert
    master_key_enc = std::move(master_key); // no except

    try {
        if (!flush(std::move(new_master))) {
            master_key_enc = std::move(old_master_key_enc);
            return false;
        }
    }
    catch (...) {
        master_key_enc = std::move(old_master_key_enc);
        throw;
    }

    return true;
}



} // namespace vault