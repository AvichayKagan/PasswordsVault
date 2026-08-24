#include <iostream>
#include "vault.hpp"
#include "safe_io.h"

using namespace vault;


class Vault::Sudo {
    private:
        crypto::SafeVar _master_key;
        bool sudo = false;

    public:
        Sudo(Vault &vault, crypto::SafeVar &&_master_password) : _master_key(vault.master_key) {
            crypto::SafeVar master_password = std::move(_master_password);
            try {
                master_password.hash(vault.salt);
                _master_key.decrypto(master_password.get(), true);
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

        crypto::SafeVar& master_key() { return _master_key; }
};


Vault::Sudo Vault::acquire_sudo(crypto::SafeVar &&master_password) {
    return Vault::Sudo(*this, std::move(master_password));
}

bool Vault::open_vault(crypto::SafeVar &master_passowrd) {
    // init session key
    session_key.random();

    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    // init the dictionary
    try {
        disk_mang.read_vault_data(dictionary, sudo.master_key(), session_key);
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
    crypto::Salt salt;
    crypto::SafeVar master_key(crypto::key_len);
    master_key.random();
    crypto::SafeVar master_key_enc = master_key;

    std::cout << "Please choose and enter a master password for the new vault: " << std::flush;
    if (safeIO::input(password.get(), config::max_password_len, true)) throw Error("Failed to take the vault password from the user.");
    password.hash(crypto::random(salt, crypto::salt_len));
    master_key_enc.encrypto(password.get());
    password.memzero();


    crypto::SafeVar dummy;
    // write empty vault - passing dummy session key
    disk_mang.atomic_write_file(dictionary, master_key, master_key_enc, dummy, salt);
}

bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd) {
    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    password.encrypto(session_key.get());
    Dict::Node *added_node = dictionary.append_node(std::move(name), std::move(password));
    try {
        disk_mang.atomic_write_file(dictionary, sudo.master_key(), master_key, session_key, salt);
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
        disk_mang.atomic_write_file(dictionary, sudo.master_key(), master_key, session_key, salt);
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
        disk_mang.atomic_write_file(dictionary, sudo.master_key(), master_key, session_key, salt);
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
        disk_mang.atomic_write_file(dictionary, sudo.master_key(), master_key, session_key, salt);
    }
    catch (...) {
        target->name = std::move(old_name);
        throw;
    }
     
    return true;
}
