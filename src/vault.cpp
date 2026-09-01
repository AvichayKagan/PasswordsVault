#include <iostream>
#include "vault.hpp"
#include "safe_io.hpp"

namespace vault {


bool Vault::flush(crypto::SafeVar master_password) {
    crypto::SafeVar master_key = master_key_enc;
    master_password.hash(salt);

    try {
        master_key.decrypto(master_password.get(), true);
    }
    catch (const crypto::Error& e) {
        if (e.code() == crypto::IncorrectPassword) return false;
        throw;
    }

    crypto::SafeVar data = session->dictionary.pack();
    data.encrypto(master_key.get());
    master_password.memzero();
    master_key.memzero();

    disk_mang.atomic_write_file(master_key_enc, salt, data);

    return true;
}


bool Vault::open_vault(crypto::SafeVar master_passowrd) {
    size_t init_buckets = disk_mang.get_size() / (config::max_name_len + config::max_password_len);
    

    // create a temp session
    auto temp = std::make_unique<Session>(init_buckets);

    // read disk
    crypto::SafeVar data = disk_mang.read_vault_data();

    master_passowrd.hash(salt);
    crypto::SafeVar master_key = master_key_enc;
    try {
        master_key.decrypto(master_passowrd.get(), true);
    }
    catch (const crypto::Error& e) {
        if (e.code() == crypto::IncorrectPassword) return false;
        throw;
    }

    data.decrypto(master_key.get(), false);
    temp->dictionary.load(std::move(data));

    // no exceptions, commit to temp
    session = std::move(temp);

    return true;
}


void Vault::init_vault(crypto::SafeVar &&master_passowrd) {
    crypto::SafeVar password_hash;
    crypto::SafeVar data;

    master_key_enc.random();
    crypto::random(salt, crypto::salt_len);
    
    password_hash = master_passowrd;
    password_hash.hash(salt);
    
    master_key_enc.encrypto(password_hash.get());
    password_hash.memzero();

    session = std::make_unique<Session>(0); // inlined open_vault for the case of empty vault that bypass the read/write chicken and egg issue
    data = session->dictionary.pack();

    flush(std::move(master_passowrd));
    
    disk_mang.atomic_write_file(master_key_enc, salt, data); 
}


bool Vault::add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_password) {
    if (session->dictionary.contains(name)) return true;
    
    password.encrypto(session->session_key.get());
    auto name_it = session->dictionary.emplace(std::move(name), std::move(password)).first; // the change to revert in case of exception

    if (master_password.get() != nullptr) {
        try {
            if (!flush(std::move(master_password))) {
                session->dictionary.erase(name_it);
                return false;
            }
        }
        catch (...) {
            session->dictionary.erase(name_it);
            throw;
        }
    }

    return true;
}


bool Vault::del_password(crypto::SafeVar &name, crypto::SafeVar &&master_password) {
    if (!session->dictionary.contains(name)) return true;

    auto node = session->dictionary.extract(name); // the change to revert in case of exception

    if (master_password.get() != nullptr) {
        try {
            if (!flush(std::move(master_password))) {
                session->dictionary.insert(std::move(node));
                return false;
            }
        }
        catch (...) {
            session->dictionary.insert(std::move(node)); // noexcept?
            throw;
        }
    }
     
    return true;
}

bool Vault::change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_password) {
    auto target = session->dictionary.find(name);
    if (target == session->dictionary.end()) throw Error("Attempt to change non exiting name password", StateError);

    password.encrypto(session->session_key.get());
    crypto::SafeVar old_password = std::move(target->second);
    target->second = std::move(password); // the change to revert in case of exception
    
    if (master_password.get() != nullptr) {
        try {
            if (!flush(std::move(master_password))) {
                target->second = std::move(old_password);
                return false;
            }
        }
        catch (...) {
            target->second = std::move(old_password);
            throw;
        }
    }
     
    return true;
}

bool Vault::change_name(crypto::SafeVar &name, crypto::SafeVar &&new_name, crypto::SafeVar &&master_password) {
    if (session->dictionary.contains(new_name)) throw Error("Attempt to change name to already existing name", StateError);

    auto target = session->dictionary.find(name);
    if (target == session->dictionary.end()) throw Error("Attempt to change non exiting name", StateError);

    auto node = session->dictionary.extract(target);
    crypto::SafeVar old_name = std::move(node.key());
    node.key() = std::move(new_name); 
    auto inserted_node = session->dictionary.insert(std::move(node)).position;

    if (master_password.get() != nullptr) {
        try {
            if (!flush(std::move(master_password))) {
                node = session->dictionary.extract(inserted_node);
                node.key() = std::move(old_name);
                session->dictionary.insert(std::move(node)); // noexcept?
                return false;
            }
        }
        catch (...) {
            node = session->dictionary.extract(inserted_node);
            node.key() = std::move(old_name);
            session->dictionary.insert(std::move(node)); // noexcept?
            throw;
        }
    }
    
    return true;
}


bool Vault::change_master(crypto::SafeVar &&new_master, crypto::SafeVar &&master_password) {
    crypto::SafeVar master_key = master_key_enc;
    crypto::SafeVar password_hash = std::move(master_password);
    password_hash.hash(salt);
    try {
        master_key.decrypto(password_hash.get(), true);
    }
    catch (const crypto::Error& e) {
        if (e.code() == crypto::IncorrectPassword) return false;
        throw;
    }
    

    crypto::SafeVar new_hash = new_master;
    new_hash.hash(salt);
    master_key.encrypto(new_hash.get());
    crypto::SafeVar old_master_key_enc = std::move(master_key_enc); // the point of revert
    master_key_enc = std::move(master_key); // no except

    try {
        if (!flush(std::move(new_master))) {
            master_key_enc = std::move(old_master_key_enc);
            return false;
        }
    }
    catch (...) {
        master_key_enc = std::move(old_master_key_enc);
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


} // namespace vault