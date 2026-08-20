#include <iostream>
#include "vault.hpp"
#include "safe_io.h"

using namespace vault;

bool Vault::sudo(const std::function<void()>& func) {  // make here way to quit (and also try again?)
    crypto::SafeVar password(config::max_password_len);
    bool master_decrypted = false;

    try {
        if (safeIO::input(password.get(), config::max_password_len, true)) throw Error("Failed to take the vault password from the user.");
        password.hash(salt);
        master_key.decrypto(password.get(), true);
        master_decrypted = true;
        func();
    }
    catch (const crypto::Error& e) {
        if (master_decrypted) master_key.encrypto(password.get());
        if (e.code() == crypto::IncorrectPassword) return false;
        throw;
    }
    catch (...) {
        if (master_decrypted) master_key.encrypto(password.get());
        throw;
    }

    master_key.encrypto(password.get());
    return true;
}

bool Vault::open_vault() {
    // init session key
    session_key.random();

    // init the dictionary
    try {
        _is_open = 
            this->sudo([this]() {
                disk_mang.read_vault_data(dictionary, master_key, session_key);
            });
    }
    catch (...) { 
        dictionary.empty(); 
        throw;
    }

    return _is_open;
}


void Vault::init_vault() {
    crypto::SafeVar password(config::max_password_len);
    crypto::Salt salt;
    crypto::SafeVar master_key(crypto::key_len);

    std::cout << "Please choose and enter a master password for the new vault: " << std::flush;
    if (safeIO::input(password.get(), config::max_password_len, true)) throw Error("Failed to take the vault password from the user.");
    password.hash(crypto::random(salt, crypto::salt_len));
    master_key.random().encrypto(password.get());
    password.memzero();

    // write the header - salt and master key
    disk_mang.write_vault_header(salt, master_key);
}

bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password) {
    return
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

bool Vault::del_password(crypto::SafeVar &name) {
    Dict::Node *target = this->dictionary.search((char *)name.get());
    if (target == nullptr) throw std::runtime_error("ASSERT ERROR");

    return
        this->sudo([&]() {
            std::unique_ptr<Dict::Node> deleted_node = this->dictionary.delete_node(target, true);
            try {
                this->disk_mang.write_vault_data(dictionary, master_key, session_key);
            }
            catch (...) {
                this->dictionary.append_node_raw(std::move(deleted_node));
                throw;
            }
        });
}