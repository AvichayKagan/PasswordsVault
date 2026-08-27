#pragma once


#include <stdio.h>
#include <stdexcept>
#include <functional>
#include "configs.hpp"
#include "dict.hpp"
#include "crypt.hpp"
#include "safe_io.hpp"
#include "disk.hpp"

namespace vault {

class Error : public config::GeneralError {
    public:
        explicit Error(const std::string& message, int errorCode) 
            : config::GeneralError(message, "VAULT", errorCode) {}
};

enum ErrorCode {
    ioError = 1,

    PremissionError = 10
};

class Vault {
    private:
        crypto::Salt salt;
        crypto::SafeVar master_key_enc;
        crypto::SafeVar session_key;
        disk::DiskManager disk_mang;
        Dict dictionary;
        bool _is_open = false;

        void init_vault();
        class Sudo;
        Sudo acquire_sudo(crypto::SafeVar &&master_password);
    
    public:

        Vault() :master_key_enc(crypto::key_len), session_key(crypto::key_len), dictionary(session_key) {
            if (disk_mang.get_size() == disk::DiskManager::pre_header_size) {
                init_vault();
            }
            else disk_mang.read_vault_header(salt, master_key_enc);
        }

        auto begin() const { return dictionary.begin(); }
        auto end() const { return dictionary.end(); }

        bool open_vault(crypto::SafeVar &master_passowrd);

        void close_vault() { dictionary.clear(); session_key.memzero(); _is_open = false; };

        bool add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd);

        bool del_password(crypto::SafeVar &name, crypto::SafeVar &&master_passowrd);

        bool change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd);

        bool change_name(crypto::SafeVar &name, crypto::SafeVar &&new_name, crypto::SafeVar &&master_passowrd);

        bool change_master(crypto::SafeVar &new_master, crypto::SafeVar &&master_passowrd);

        bool exists(crypto::SafeVar &name) { return dictionary.contains(name); }

        crypto::SafeVar search(crypto::SafeVar &name) { 
            crypto::SafeVar ret;
            auto it = dictionary.find(name);
            if (it != dictionary.end()) {
                ret = it->second;
                ret.decrypto(session_key.get(), false);
            }
            return ret;
        }

        long long get_size() { return disk_mang.get_size(); }

        unsigned int get_count() { return dictionary.size(); }

        bool is_empty() { return dictionary.empty(); }

        bool is_open() { return _is_open; }
};

}