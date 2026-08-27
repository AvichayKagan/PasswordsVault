#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "dict.hpp"


crypto::SafeVar Dict::pack(crypto::SafeVar &session_key, crypto::SafeVar &master_key) {
    size_t write_len = size() * (config::max_name_len + config::max_password_len);
    crypto::SafeVar vault_data(write_len);
    int j = 0;
    
    // load the buffer
    for (auto& i : *this) {
        crypto::SafeVar& password = i.second;

        // write the name
        std::memcpy(vault_data.get() + j, i.first.get(), config::max_name_len);
        j += config::max_name_len;

        // write the password
        password.decrypto(session_key.get(), false);
        std::memcpy(vault_data.get() + j, password.get(), config::max_password_len);
        j += config::max_password_len;
        password.encrypto(session_key.get());
    }
    vault_data.encrypto(master_key.get());

    return vault_data;
}