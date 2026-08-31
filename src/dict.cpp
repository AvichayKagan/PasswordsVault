#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dict.hpp"


crypto::SafeVar Dict::pack() const {
    size_t write_len = size() * (config::max_name_len + config::max_password_len);
    crypto::SafeVar vault_data(write_len);
    crypto::SafeVar password;
    int j = 0;
    
    // load the buffer
    for (auto& i : *this) {
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

    return vault_data;
}

void Dict::load(crypto::SafeVar &data){
    size_t read_len = data.get_size();
    size_t i = 0;
    // load the dictionary
    while (i < read_len - crypto::SafeVar::encryptoion_buff_len) {
        crypto::SafeVar name(config::max_name_len);
        crypto::SafeVar password(config::max_password_len);

        // set the name
        std::memcpy(name.get(), data.get() + i, config::max_name_len);
        i += config::max_name_len;

        // set the password
        std::memcpy(password.get(), data.get() + i, config::max_password_len);
        password.encrypto(session_key.get());
        i += config::max_password_len;

        emplace(std::move(name), std::move(password));
    }
}