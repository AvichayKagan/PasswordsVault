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

    PremissionError = 10,

    InitError = 20
};

class Vault {
    private:
        class DictPtr {
            private:
                std::unique_ptr<Dict> ptr;
            public:
                DictPtr() = default;
                DictPtr(crypto::SafeVar &&data) : ptr(std::make_unique<Dict>(std::move(data))) {}
                void reset() { ptr.reset(); }
                explicit operator bool() const { return ptr.get(); }
                Dict* operator->() const { 
                    if (!ptr) throw Error("Attempt accessing a closed vault.", PremissionError); 
                    return ptr.get(); 
                }
        };

        crypto::Salt salt;
        crypto::SafeVar master_key_enc;
        disk::DiskManager disk_mang;
        DictPtr dictionary; // add some sort of check that this is not null for all operations to prevent segfault
        
        void init_vault(crypto::SafeVar &&master_password);
    public:

        Vault(crypto::SafeVar &&master_password = crypto::SafeVar()) :master_key_enc(crypto::key_len) {
            if (master_password.get() != nullptr) {
                init_vault(std::move(master_password));
            }
            else if (disk_mang.get_size() != disk::DiskManager::pre_header_size) {
                disk_mang.read_vault_header(salt, master_key_enc);
            }
            else throw Error("Vault file does not exist", InitError);
        }

        void flush(crypto::SafeVar master_password);

        bool open_vault(crypto::SafeVar &&master_passowrd);

        void close_vault() { dictionary.reset(); };

        long long get_size() { return disk_mang.get_size(); }

        bool is_open() const { return (bool)dictionary; }


        auto begin() const { return dictionary->begin(); }
        auto end() const { return dictionary->end(); }

        bool add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd = crypto::SafeVar());

        bool del_password(crypto::SafeVar &name, crypto::SafeVar &&master_passowrd = crypto::SafeVar());

        bool change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd = crypto::SafeVar());

        bool change_name(crypto::SafeVar &&name, crypto::SafeVar &new_name, crypto::SafeVar &&master_passowrd = crypto::SafeVar());

        bool change_master(crypto::SafeVar &&new_master, crypto::SafeVar &&master_passowrd);

        bool contains(crypto::SafeVar &name) { return dictionary->contains(name); }

        crypto::SafeVar search(crypto::SafeVar &name) { return dictionary->get_password(name); }
 
        unsigned int get_count() { return dictionary->size(); }

        bool is_empty() { return dictionary->empty(); }

        crypto::SafeVar get_master_key(crypto::SafeVar &&master_password);
};

}