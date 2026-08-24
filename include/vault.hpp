#pragma once


#include <stdio.h>
#include <stdexcept>
#include <functional>
#include "configs.hpp"
#include "dict.hpp"
#include "crypt.hpp"
#include "disk.hpp"

namespace vault {

class Error : public config::GeneralError {
    public:
        explicit Error(const std::string& message, int errorCode = 1) 
            : config::GeneralError(message, "VAULT", errorCode) {}
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
        void flush(Sudo &sudo_token);
    
    public:

        Vault() :master_key_enc(crypto::key_len), session_key(crypto::key_len) {
            if (disk_mang.get_size() == disk::DiskManager::pre_header_size) {
                init_vault();
            }
            else disk_mang.read_vault_header(salt, master_key_enc);
        }

        bool open_vault(crypto::SafeVar &master_passowrd);

        void close_vault() { dictionary.empty(); session_key.memzero(); _is_open = false; };

        bool add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd);

        bool del_password(crypto::SafeVar &name, crypto::SafeVar &&master_passowrd);

        bool change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd);

        bool change_name(crypto::SafeVar &name, crypto::SafeVar &&new_name, crypto::SafeVar &&master_passowrd);

        bool change_master(crypto::SafeVar &new_master, crypto::SafeVar &&master_passowrd);

        bool exists(crypto::SafeVar &name) { return (dictionary.search((char *)name.get()) == nullptr) ? false : true; }

        crypto::SafeVar search(crypto::SafeVar &name) {
            Dict::Node *node = dictionary.search((char *)name.get());
            crypto::SafeVar ret;

            if (node != nullptr) {
                ret = node->password;
                ret.decrypto(session_key.get(), false);
            }

            return ret;
        }

        long long get_size() { return disk_mang.get_size(); }

        unsigned int get_count() { return dictionary.get_count(); }

        void list_all() {
            for (Dict::Node *i = dictionary.get_head(); i != nullptr; i = i->get_next() ) {
                std::cout << i->name.get() << std::endl; // must safely print this!
            }
        }

        bool is_empty() { return !dictionary.get_head(); }

        bool is_open() { return _is_open; }
};

}