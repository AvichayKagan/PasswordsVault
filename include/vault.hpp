#pragma once


#include <stdio.h>
#include <stdexcept>
#include <functional>
#include "configs.hpp"
#include "dict.hpp"
#include "crypt.hpp"
#include "disk.hpp"


class Vault {
    private:
        crypto::Salt salt;
        crypto::SafeVar master_key;
        crypto::SafeVar session_key;
        DiskManager disk_mang;
        Dict dictionary;
        bool _is_open = false;


        void init_vault();
    
    public:

        Vault() :master_key(crypto::key_len), session_key(crypto::key_len) {
            if (disk_mang.get_size() == DiskManager::pre_header_size) init_vault();

            disk_mang.read_vault_header(this->salt, this->master_key);
        }

        void open_vault();

        void close_vault() { this->dictionary.empty(); _is_open = false; };

        void sudo(const std::function<void()>& func);

        void add_password(crypto::SafeVar &&name, crypto::SafeVar &&password);

        bool del_password(crypto::SafeVar &&name);

        bool exists(crypto::SafeVar &name) { return (dictionary.search((char *)name.get()) == nullptr) ? false : true; }

        crypto::SafeVar search(crypto::SafeVar &name) {
            Dict::Node *node = dictionary.search((char *)name.get());
            crypto::SafeVar ret;

            if (node == nullptr) ret = node->get_password().decrypto(session_key.get(), false);

            return ret;
        }

        long long get_size() { return disk_mang.get_size(); }

        void list_all() {
            for (Dict::Node *i = dictionary.get_head(); i != nullptr; i = i->get_next() ) {
                std::cout << i->get_name().get() << std::endl;
            }
        }

        bool is_open() { return _is_open; }
};