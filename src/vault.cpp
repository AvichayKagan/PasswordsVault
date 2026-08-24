#include <iostream>
#include "vault.hpp"
#include "safe_io.h"

using namespace vault;


class Vault::Sudo {
    private:
        bool sudo = false;

    public:
        crypto::SafeVar master_key;

        Sudo(Vault &vault, crypto::SafeVar &&_master_password) : master_key(vault.master_key_enc) {
            crypto::SafeVar master_password = std::move(_master_password);
            try {
                master_password.hash(vault.salt);
                master_key.decrypto(master_password.get(), true);
                sudo = true;
            }
            catch (const crypto::Error& e) {
                if (e.code() != crypto::IncorrectPassword) throw;
            }
        }

        ~Sudo() = default;
        Sudo(const Sudo&) = delete;
        Sudo& operator=(const Sudo&) = delete;
        Sudo(Sudo&&) = delete;
        Sudo& operator=(Sudo&&) = delete;


        explicit operator bool() { return sudo; }
};


Vault::Sudo Vault::acquire_sudo(crypto::SafeVar &&master_password) {
    return Vault::Sudo(*this, std::move(master_password));
}

void Vault::flush(Sudo &sudo_token) { 
    disk_mang.atomic_write_file(dictionary, sudo_token.master_key, master_key_enc, session_key, salt); 
}

bool Vault::open_vault(crypto::SafeVar &master_passowrd) {
    // init session key
    session_key.random();

    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    // init the dictionary
    try {
        disk_mang.read_vault_data(dictionary, sudo.master_key, session_key);
    }
    catch (...) { 
        dictionary.empty(); 
        throw;
    }

    _is_open = true;
    return true;
}


void Vault::init_vault() {
    crypto::SafeVar password(config::max_password_len);
    crypto::SafeVar password_hash;

    master_key_enc.random();
    crypto::random(salt, crypto::salt_len);

    std::cout << "Please choose and enter a master password for the new vault: " << std::flush;
    if (safeIO::input(password.get(), config::max_password_len, true)) throw Error("Failed to take the vault password from the user.");
    
    password_hash = password;
    password_hash.hash(salt);
    master_key_enc.encrypto(password_hash.get());
    password_hash.memzero();

    auto sudo = acquire_sudo(std::move(password));
    if (!sudo) throw std::runtime_error("ASSERT ERROR");
    flush(sudo);
}

bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd) {
    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    password.encrypto(session_key.get());
    Dict::Node *added_node = dictionary.append_node(std::move(name), std::move(password));
    try {
        flush(sudo);
    }
    catch (...) {
        dictionary.delete_node(added_node, false);
        throw;
    }

    return true;
}

bool Vault::del_password(crypto::SafeVar &name, crypto::SafeVar &&master_passowrd) {
    Dict::Node *target = dictionary.search((char *)name.get());
    if (target == nullptr) throw std::runtime_error("ASSERT ERROR");

    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    std::unique_ptr<Dict::Node> deleted_node = dictionary.delete_node(target, true);
    try {
        flush(sudo);
    }
    catch (...) {
        dictionary.append_node_raw(std::move(deleted_node));
        throw;
    }
     
    return true;
}

bool Vault::change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd) {
    Dict::Node *target = dictionary.search((char *)name.get());
    if (target == nullptr) throw std::runtime_error("ASSERT ERROR");

    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    crypto::SafeVar old_password = target->password;
    password.encrypto(session_key.get());
    target->password = std::move(password);
    try {
        flush(sudo);
    }
    catch (...) {
        target->password = std::move(old_password);
        throw;
    }
     
    return true;
}

bool Vault::change_name(crypto::SafeVar &name, crypto::SafeVar &&new_name, crypto::SafeVar &&master_passowrd) {
     Dict::Node *target = dictionary.search((char *)name.get());
    if (target == nullptr) throw std::runtime_error("ASSERT ERROR");

    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    crypto::SafeVar old_name = target->name;
    target->name = std::move(new_name);
    try {
        flush(sudo);
    }
    catch (...) {
        target->name = std::move(old_name);
        throw;
    }
     
    return true;
}

bool Vault::change_master(crypto::SafeVar &new_master, crypto::SafeVar &&master_password) {
    auto sudo = acquire_sudo(std::move(master_password));
    if (!sudo) return false;

    crypto::SafeVar old_master_key_enc = master_key_enc;
    try {
        new_master.hash(salt);
        master_key_enc = sudo.master_key;
        master_key_enc.encrypto(new_master.get());
        flush(sudo);
    }
    catch (...) {
        master_key_enc = std::move(old_master_key_enc);
        throw;
    }
     
    return true;
}

