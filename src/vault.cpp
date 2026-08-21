#include <iostream>
#include "vault.hpp"
#include "safe_io.h"

using namespace vault;

bool Vault::sudo(const std::function<void()>& func, crypto::SafeVar &master_password) { 
    bool master_decrypted = false;
    
    try {
        master_password.hash(salt);
        master_key.decrypto(master_password.get(), true);
        master_decrypted = true;
        func();
    }
    catch (const crypto::Error& e) {
        if (master_decrypted) master_key.encrypto(master_password.get());
        if (e.code() == crypto::IncorrectPassword) return false;
        throw;
    }
    catch (...) {
        if (master_decrypted) master_key.encrypto(master_password.get());
        throw;
    }

    master_key.encrypto(master_password.get());
    return true;
}

bool Vault::open_vault(crypto::SafeVar &master_passowrd) {
    // init session key
    session_key.random();

    // init the dictionary
    try {
        _is_open = 
            this->sudo([this]() {
                disk_mang.read_vault_data(dictionary, master_key, session_key);
            }, master_passowrd);
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

bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &master_passowrd) {
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
        }, master_passowrd);
}

bool Vault::del_password(crypto::SafeVar &name, crypto::SafeVar &master_passowrd) {
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
        }, master_passowrd);
}