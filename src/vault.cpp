#include <iostream>
#include "vault.hpp"
#include "safe_io.h"


void Vault::sudo(const std::function<void()>& func) { 
    SafeVar password(MAX_PASSWORD_LENGTH);

    try {
        if (input(password.get(), MAX_PASSWORD_LENGTH, true)) throw std::runtime_error("Failed to take the vault password from the user.");
        password.hash(salt);
        master_key.decrypt(password.get(), true);
        func();
    }
    catch (...) {
        master_key.encrypt(password.get());
        throw;
    }

    master_key.encrypt(password.get());
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
    SafeVar password(MAX_PASSWORD_LENGTH);
    SafeVar salt(SALT_LEN);
    SafeVar master_key(KEY_LEN);

    if (input(password.get(), MAX_PASSWORD_LENGTH, true)) throw std::runtime_error("Failed to take the vault password from the user.");
    password.hash(salt.random().get());
    master_key.random().encrypt(password.get());
    password.memzero();

    // write the header - salt and master key
    disk_mang.write_vault_header(salt.get(), master_key);
}