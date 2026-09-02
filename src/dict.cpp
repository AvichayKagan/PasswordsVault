#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dict.hpp"


crypto::SafeVar Dict::pack() const {
    size_t write_len = config::vault_file_padding_factor * (1 + (map.size() / config::vault_file_padding_factor)) * (config::max_name_len + config::max_password_len);
    crypto::SafeVar vault_data(write_len);
    crypto::SafeVar password;
    size_t j = 0;
    
    // load the buffer
    for (auto& i : map) {
        // get the password
        password = i.second;
        password.decrypto(session_key.get(), false);

        // write the name
        std::memcpy(vault_data.get() + j, i.first.get(), config::max_name_len);
        j += config::max_name_len;

        // write the password
        std::memcpy(vault_data.get() + j, password.get(), config::max_password_len);
        j += config::max_password_len;
    }
    if (j < write_len) {
        vault_data.get()[j++] = '\0';
        crypto::random(vault_data.get() + j, write_len- j);
    }

    return vault_data;
}

void Dict::load(crypto::SafeVar data){
    size_t read_len = data.get_size();
    size_t i = 0;

    // load the dictionary
    while (i < read_len - crypto::SafeVar::encryptoion_buff_len) {
        crypto::SafeVar name(config::max_name_len);
        crypto::SafeVar password(config::max_password_len);

        // set the name
        std::memcpy(name.get(), data.get() + i, config::max_name_len);
        if (*name.get() == '\0') break;
        i += config::max_name_len;

        // set the password
        std::memcpy(password.get(), data.get() + i, config::max_password_len);
        i += config::max_password_len;

        emplace(std::move(name), std::move(password));
    }
}

std::pair<Dict::Map::iterator, bool> Dict::emplace(crypto::SafeVar &&name, crypto::SafeVar &&password) {
    password.encrypto(session_key.get());
    return map.emplace(std::move(name), std::move(password));
}

crypto::SafeVar Dict::change_password(crypto::SafeVar &name, crypto::SafeVar &&password) {
    auto target = map.find(name);
    if (target == map.end()) throw std::runtime_error("Attempt to change non exiting name password"); // change it

    password.encrypto(session_key.get());
    target->second.decrypto(session_key.get(), false); // point of revert

    crypto::SafeVar old_password = std::move(target->second); // no except
    target->second = std::move(password); // no except

    return old_password;
}


Dict::Map::iterator Dict::change_name(crypto::SafeVar &name, crypto::SafeVar &&new_name) {
    if (map.contains(new_name)) throw std::runtime_error("Attempt to change name to already existing name"); // change it

    auto target = map.find(name);
    if (target == map.end()) throw std::runtime_error("Attempt to change non exiting name"); // change it

    auto node = map.extract(target); // from here cannot except
    node.key() = std::move(new_name);
    return map.insert(std::move(node)).position;
}

crypto::SafeVar Dict::get_password(crypto::SafeVar &name) { 
    crypto::SafeVar ret;
    auto it = map.find(name);
    if (it != map.end()) {
        ret = it->second;
        ret.decrypto(session_key.get(), false);
    }
    return ret;
}