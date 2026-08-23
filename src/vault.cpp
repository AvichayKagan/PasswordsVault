#include <iostream>
#include "vault.hpp"
#include "safe_io.h"

using namespace vault;


class Vault::Sudo {
    private:
        Vault &vault;
        crypto::SafeVar master_password;
        bool sudo = false;

    public:
        Sudo(Vault &_vault, crypto::SafeVar &&_master_password) :vault(_vault), master_password(std::move(_master_password)) {
           try {
                master_password.hash(vault.salt);
                vault.master_key.decrypto(master_password.get(), true);
                sudo = true;
            }
            catch (const crypto::Error& e) {
                if (e.code() != crypto::IncorrectPassword) throw;
            }
            catch (...) {
                throw;
            }
        }

        ~Sudo() {
            if (sudo) vault.master_key.encrypto(master_password.get());
        }

        Sudo(const Sudo&) = delete;
        Sudo& operator=(const Sudo&) = delete;
        Sudo(Sudo&&) = delete;
        Sudo& operator=(Sudo&&) = delete;


        explicit operator bool() { return sudo; }
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
        disk_mang.read_vault_data(dictionary, master_key, session_key);
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

    // write the header - salt and master key
    disk_mang.write_vault_header(salt, master_key_enc);
    // write empty data - passing dummy session key
    crypto::SafeVar dummy;
    disk_mang.write_vault_data(dictionary, master_key, dummy);
}

bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd) {
    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    password.encrypto(session_key.get());
    Dict::Node *added_node = dictionary.append_node(std::move(name), std::move(password));
    try {
        disk_mang.write_vault_data(dictionary, master_key, session_key); // make sure it wont corrupt the data!
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
        disk_mang.write_vault_data(dictionary, master_key, session_key);
    }
    catch (...) {
        dictionary.append_node_raw(std::move(deleted_node));
        throw;
    }
     
    return true;
}