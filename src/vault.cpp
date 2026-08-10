#include <iostream>
#include "vault.hpp"
#include "safe_io.h"

using namespace crypto;

void Vault::sudo(const std::function<void()>& func) { 
    SafeVar password(config::max_password_len);

    try {
        std::cout << "Please enter the master password to continue with this operation: " << std::flush;
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
        this->sudo([this]() {
            disk_mang.read_vault_data(dictionary, master_key, session_key);
        });
    }
    catch (...) {
        dictionary.empty();
        throw;
    }

    _is_open = true;
}


void Vault::init_vault() {
    SafeVar password(config::max_password_len);
    Salt salt;
    SafeVar master_key(key_len);

    std::cout << "Please choose and enter a master password for the new vault: " << std::flush;
    if (safeIO::input(password.get(), config::max_password_len, true)) throw std::runtime_error("Failed to take the vault password from the user.");
    password.hash(random(salt, salt_len));
    master_key.random().encrypto(password.get());
    password.memzero();

    // write the header - salt and master key
    disk_mang.write_vault_header(salt, master_key);
}

void Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password) {
    this->sudo([&]() {
        password.encrypto(session_key.get());
        Dict::Node *added_node = this->dictionary.append_node(std::move(name), std::move(password));
        try {
            this->disk_mang.write_vault_data(dictionary, master_key, session_key); // make sure it wont corrupt the data!
        }
        catch (...) {
            this->dictionary.delete_node(added_node, false);
            throw;
        }
    });
}


bool Vault::del_password(crypto::SafeVar &&name) {
    int ret = true;
    this->sudo([&]() {
        Dict::Node *target = this->dictionary.search((char *)name.get());
        if (target == nullptr) {
            ret = false; 
            return;
        }
        std::unique_ptr<Dict::Node> deleted_node = this->dictionary.delete_node(target, true);
        try {
            this->disk_mang.write_vault_data(dictionary, master_key, session_key);
        }
        catch (...) {
            this->dictionary.append_node_raw(std::move(deleted_node));
            throw;
        }
    });

    return ret;
}