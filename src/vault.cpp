#include <iostream>
#include "vault.hpp"
#include "safe_io.hpp"

namespace vault {


class Vault::Sudo {
    private:
        Vault &vault;
        crypto::SafeVar master_key;
        bool sudo = false;

    public:

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

        void encrypt(crypto::SafeVar &data) { 
            if (!sudo) throw Error("Sudo token is invalid or has been expired", PremissionError);

            data.encrypto(master_key.get()); 
            master_key.memzero();
            sudo = false;
        }

        void decrypt(crypto::SafeVar &data) { 
            if (!sudo) throw Error("Sudo token is invalid or has been expired", PremissionError);

            data.decrypto(master_key.get(), false); 
            master_key.memzero();
            sudo = false;
        }

        void change_master(crypto::SafeVar &new_master) {
            if (!sudo) throw Error("Sudo token is invalid or has been expired", PremissionError);
        
            new_master.hash(vault.salt);
            vault.master_key_enc = master_key; // if throw master_key_enc is remain as it is
            vault.master_key_enc.encrypto(new_master.get()); //canont throw
        }
      
};


Vault::Sudo Vault::acquire_sudo(crypto::SafeVar &&master_password) {
    return Vault::Sudo(*this, std::move(master_password));
}


bool Vault::open_vault(crypto::SafeVar &&master_passowrd) {
    size_t init_buckets = disk_mang.get_size() / (config::max_name_len + config::max_password_len);
    

    // create a temp session
    auto temp = std::make_unique<Session>(init_buckets);

    // read disk
    crypto::SafeVar data = disk_mang.read_vault_data();

    { // use sudo
        auto sudo = acquire_sudo(std::move(master_passowrd));
        if (!sudo) return false;
        sudo.decrypt(data);
        temp->dictionary.load(data);
    } // sudo destroyed here

    // no exceptions, commit to temp
    session = std::move(temp);

    return true;
}


void Vault::init_vault() {
    crypto::SafeVar password(config::max_password_len);
    crypto::SafeVar password_hash;
    crypto::SafeVar password_to_open;
    crypto::SafeVar data;

    master_key_enc.random();
    crypto::random(salt, crypto::salt_len);

    std::cout << "Please choose and enter a master password for the new vault: " << std::flush;
    if (safeio::input(password.get(), config::max_password_len, true)) throw Error("Failed to take the vault password from the user.", ioError);
    
    password_hash = password;
    password_to_open = password;

    password_hash.hash(salt);
    master_key_enc.encrypto(password_hash.get());
    password_hash.memzero();

    open_vault(std::move(password_to_open));

    {
        auto sudo = acquire_sudo(std::move(password));
        data = session->dictionary.pack();
        sudo.encrypt(data);
    }
    
    disk_mang.atomic_write_file(master_key_enc, salt, data); 
}

bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd) {
    crypto::SafeVar data;
    Dict::iterator name_it = session->dictionary.end();

    try {
        { // use sudo
            auto sudo = acquire_sudo(std::move(master_passowrd));
            if (!sudo) return false;

            // add the password to dictionary
            password.encrypto(session->session_key.get());
            name_it = session->dictionary.emplace(std::move(name), std::move(password)).first; // the change to revert in case of exception

            data = session->dictionary.pack();
            sudo.encrypt(data);
        } // sudo destroyed here

        disk_mang.atomic_write_file(master_key_enc, salt, data); 
    }
    catch (...) {
        if (name_it != session->dictionary.end()) session->dictionary.erase(name_it);
        throw;
    }

    return true;
}


bool Vault::del_password(crypto::SafeVar &name, crypto::SafeVar &&master_passowrd) {
    Dict::node node;
    crypto::SafeVar data;
    
    try {
        { //use sudo
            auto sudo = acquire_sudo(std::move(master_passowrd));
            if (!sudo) return false;

            node = session->dictionary.extract(name); // the change to revert in case of exception

            data = session->dictionary.pack();
            sudo.encrypt(data);
        } // sudo destroyed here

        disk_mang.atomic_write_file(master_key_enc, salt, data);
    }
    catch (...) {
        if (!node.empty()) session->dictionary.insert(std::move(node)); // noexcept?
        throw;
    }
     
    return true;
}

bool Vault::change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd) {
    Dict::iterator target;
    crypto::SafeVar data;
    crypto::SafeVar old_password;
    bool changed = false;
    
    try {
        { // use sudo
            auto sudo = acquire_sudo(std::move(master_passowrd));
            if (!sudo) return false;

            target = session->dictionary.find(name);
            old_password = target->second;
            password.encrypto(session->session_key.get());
            target->second = std::move(password); // the change to revert in case of exception
            changed = true;

            data = session->dictionary.pack();
            sudo.encrypt(data);
        } // sudo destroyed here

        disk_mang.atomic_write_file(master_key_enc, salt, data);
    }
    catch (...) {
        if (changed) target->second = std::move(old_password);
        throw;
    }
     
    return true;
}

bool Vault::change_name(crypto::SafeVar &name, crypto::SafeVar &&new_name, crypto::SafeVar &&master_passowrd) {
    Dict::node node;
    Dict::iterator inserted_node;
    crypto::SafeVar old_name;
    crypto::SafeVar data;
    bool revert = false;

    try {
        { // use sudo
            auto sudo = acquire_sudo(std::move(master_passowrd));
            if (!sudo) return false;

            node = session->dictionary.extract(name); // the change to revert in case of exception
            revert = true;

            old_name = std::move(node.key());
            node.key() = std::move(new_name);

            inserted_node = session->dictionary.insert(std::move(node)).position;

            data = session->dictionary.pack();
            sudo.encrypt(data);
        } // sudo destroyed here

        disk_mang.atomic_write_file(master_key_enc, salt, data);
    }
    catch (...) {
        if (revert) {
            node = session->dictionary.extract(inserted_node);
            node.key() = std::move(old_name);
            session->dictionary.insert(std::move(node)); // noexcept?
        }
        throw;
    }
    
    return true;
}

bool Vault::change_master(crypto::SafeVar &new_master, crypto::SafeVar &&master_password) {
    crypto::SafeVar old_master_key_enc = master_key_enc;
    crypto::SafeVar data;
    bool changed = false;

    try {
        { // use sudo
            auto sudo = acquire_sudo(std::move(master_password));
            if (!sudo) return false;

            sudo.change_master(new_master); // the change to revert in case of exception
            changed = true;

            data = session->dictionary.pack();
            sudo.encrypt(data);
        } // sudo destroyed here

        disk_mang.atomic_write_file(master_key_enc, salt, data);
    }
    catch (...) {
        if (changed) master_key_enc = std::move(old_master_key_enc);
        throw;
    }

    return true;
}


crypto::SafeVar Vault::search(crypto::SafeVar &name) { 
    crypto::SafeVar ret;
    auto it = session->dictionary.find(name);
    if (it != session->dictionary.end()) {
        ret = it->second;
        ret.decrypto(session->session_key.get(), false);
    }
    return ret;
}


}