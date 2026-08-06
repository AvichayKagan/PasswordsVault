#include <iostream>
#include "vault.hpp"
#include "safe_io.h"


void Vault::sudo(const std::function<void()>& func) { 
    SafeVar password(MAX_PASSWORD_LENGTH);

    try {
        std::cout << "Please Enter Your Vault Password: " << std::flush;
        if (input(password.get_ptr(false), MAX_PASSWORD_LENGTH, true)) throw std::runtime_error("Failed to take the vault passwrod from the user.");
        password.hash(this->salt);
        (this->master_key).decrypt(password.get_ptr(false), true);
        func();
    }
    catch (...) {
        (this->master_key).encrypt(password.get_ptr(false));
        password.memzero();
        throw;
    }

    (this->master_key).encrypt(password.get_ptr(false));
    password.memzero();
}

void Vault::open_vault() {
    // init session key
    this->session_key.random();

    // init the dictionary
    try {
        (*this).sudo([this]() {
            this->disk_mang.read_vault_data(this->dictionary, this->master_key, this->session_key);
        });
    }
    catch (...) {
        this->dictionary.empty();
        throw;
    }

    this->is_open = true;
}