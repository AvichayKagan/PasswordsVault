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
        class Session {
        public:
            crypto::SafeVar session_key;
            Dict dictionary;

            explicit Session(size_t vault_count) : session_key(crypto::key_len, true), dictionary(session_key, vault_count) {}
            ~Session() = default;
            Session(const Session&) = delete;
            Session& operator=(const Session&) = delete;
            Session(Session&&) = delete;
            Session& operator=(Session&&) = delete; 
        };

        crypto::Salt salt;
        crypto::SafeVar master_key_enc;
        disk::DiskManager disk_mang;
        std::unique_ptr<Session> session;

        void init_vault();
        class Sudo;
        Sudo acquire_sudo(crypto::SafeVar &&master_password);
    
    public:

        Vault() :master_key_enc(crypto::key_len) {
            if (disk_mang.get_size() == disk::DiskManager::pre_header_size) {
                init_vault();
            }
            else disk_mang.read_vault_header(salt, master_key_enc);
        }

        bool open_vault(crypto::SafeVar &&master_passowrd);

        void close_vault() { session.reset(); };

        long long get_size() { return disk_mang.get_size(); }

        bool is_open() const { return session != nullptr; }


        auto begin() const { return session->dictionary.begin(); }
        auto end() const { return session->dictionary.end(); }

        bool add_password(crypto::SafeVar &&name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd);

        bool del_password(crypto::SafeVar &name, crypto::SafeVar &&master_passowrd);

        bool change_password(crypto::SafeVar &name, crypto::SafeVar &&password, crypto::SafeVar &&master_passowrd);

        bool change_name(crypto::SafeVar &name, crypto::SafeVar &&new_name, crypto::SafeVar &&master_passowrd);

        bool change_master(crypto::SafeVar &&new_master, crypto::SafeVar &&master_passowrd);

        bool contains(crypto::SafeVar &name) { return session->dictionary.contains(name); }

        crypto::SafeVar search(crypto::SafeVar &name);

        unsigned int get_count() { return session->dictionary.size(); }

        bool is_empty() { return session->dictionary.empty(); }
};

}