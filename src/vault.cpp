#include <iostream>
#include "vault.hpp"
#include "safe_io.h"

using namespace vault;


class Vault::Sudo {
    private:
        bool sudo = false;
        Vault &vault;

    public:
        crypto::SafeVar master_key;

        Sudo(Vault &_vault, crypto::SafeVar &&_master_password) : vault(_vault), master_key(vault.master_key_enc) {
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

        void write() { 
            if (!sudo) throw Error("Attempted to make sudo operation with no sudo privileges", PremissionError);

            vault.disk_mang.atomic_write_file(vault.dictionary, master_key, vault.master_key_enc, vault.session_key, vault.salt); 
        }

        void read() {
            if (!sudo) throw Error("Attempted to make sudo operation with no sudo privileges", PremissionError);

            try {
                vault.disk_mang.read_vault_data(vault.dictionary, master_key, vault.session_key);
            }
            catch (...) { 
                vault.dictionary.clear(); 
                throw;
            }

            vault._is_open = true;
        }

        void change_master(crypto::SafeVar &new_master) {
            if (!sudo) throw Error("Attempted to make sudo operation with no sudo privileges", PremissionError);

            crypto::SafeVar old_master_key_enc = vault.master_key_enc;
            try {
                new_master.hash(vault.salt);
                vault.master_key_enc = master_key;
                vault.master_key_enc.encrypto(new_master.get());
                write();
            }
            catch (...) {
                vault.master_key_enc = std::move(old_master_key_enc);
                throw;
            }
        }

      
};


Vault::Sudo Vault::acquire_sudo(crypto::SafeVar &&master_password) {
    return Vault::Sudo(*this, std::move(master_password));
}


bool Vault::open_vault(crypto::SafeVar &master_passowrd) {
    // init session key
    session_key.random();

    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    sudo.read(); // read the vault file using sudo

    return true;
}


void Vault::init_vault() {
    crypto::SafeVar password(config::max_password_len);
    crypto::SafeVar password_hash;

    master_key_enc.random();
    crypto::random(salt, crypto::salt_len);

    std::cout << "Please choose and enter a master password for the new vault: " << std::flush;
    if (safeIO::input(password.get(), config::max_password_len, true)) throw Error("Failed to take the vault password from the user.", ioError);
    
    password_hash = password;
    password_hash.hash(salt);
    master_key_enc.encrypto(password_hash.get());
    password_hash.memzero();

    auto sudo = acquire_sudo(std::move(password));
    if (!sudo) throw std::runtime_error("ASSERT ERROR");
    sudo.write();
}

bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd) {
    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    password.encrypto(session_key.get());
    auto name_it = dictionary.emplace(std::move(name), std::move(password)).first;
    try {
        sudo.write();
    }
    catch (...) {
        dictionary.erase(name_it);
        throw;
    }

    return true;
}


bool Vault::del_password(crypto::SafeVar &name, crypto::SafeVar &&master_passowrd) {
    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    auto node = dictionary.extract(name);
    try {
        sudo.write();
    }
    catch (...) {
        dictionary.insert(std::move(node)); // noexcept?
        throw;
    }
     
    return true;
}

bool Vault::change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd) {
    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    auto target = dictionary.find(name);
    crypto::SafeVar old_password = target->second;
    password.encrypto(session_key.get());
    target->second = std::move(password);
    try {
        sudo.write();
    }
    catch (...) {
        target->second = std::move(old_password);
        throw;
    }
     
    return true;
}

bool Vault::change_name(crypto::SafeVar &name, crypto::SafeVar &&new_name, crypto::SafeVar &&master_passowrd) {
    auto sudo = acquire_sudo(std::move(master_passowrd));
    if (!sudo) return false;

    auto node = dictionary.extract(name);
    crypto::SafeVar old_name = std::move(node.key());
    node.key() = std::move(new_name);
    crypto::SafeVar &new_name_ref = node.key();
    dictionary.insert(std::move(node));
    try {
        sudo.write();
    }
    catch (...) {
        node = dictionary.extract(new_name_ref);
        node.key() = std::move(old_name);
        dictionary.insert(std::move(node)); // noexcept?
        throw;
    }
    
    return true;
}

bool Vault::change_master(crypto::SafeVar &new_master, crypto::SafeVar &&master_password) {
    auto sudo = acquire_sudo(std::move(master_password));
    if (!sudo) return false;

    sudo.change_master(new_master);
     
    return true;
}

