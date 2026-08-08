#include <iostream>
#include "vault.hpp"
#include "safe_io.h"

using namespace crypto;

void Vault::sudo(const std::function<void()>& func) { 
    SafeVar password(config::max_password_len);

    try {
        if (safeIO::input(password.get(), config::max_password_len, true)) throw std::runtime_error("Failed to take the vault password from the user.");
        password.hash(salt);
        master_key.decrypto(password.get(), true);
        func();
    }
    catch (...) {
        master_key.encrypto(password.get());
        throw;
    }

    master_key.encrypto(password.get());
}

void Vault::open_vault() {
    // init session key
    session_key.random();

    // init the dictionary
    try {
        (*this).sudo([this]() {
            disk_mang.read_vault_data(dictionary, master_key, session_key);
        });
    }
    catch (...) {
        dictionary.empty();
        throw;
    }

    is_open = true;
}


void Vault::init_vault() {
    SafeVar password(config::max_password_len);
    Salt salt;
    SafeVar master_key(key_len);

    if (safeIO::input(password.get(), config::max_password_len, true)) throw std::runtime_error("Failed to take the vault password from the user.");
    password.hash(random(salt, salt_len));
    master_key.random().encrypto(password.get());
    password.memzero();

    // write the header - salt and master key
    disk_mang.write_vault_header(salt, master_key);
}