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
        Dict dictionary;
        DiskManager disk_mang;
        bool is_open = false;


        void init_vault();
    
    public:

        Vault() :master_key(crypto::key_len), session_key(crypto::key_len) {
            if (disk_mang.get_size() == DiskManager::pre_header_size) init_vault();

            disk_mang.read_vault_header(this->salt, this->master_key);
        }

        void open_vault();

        void lock_vault() { this->dictionary.empty(); is_open = false; };

        void sudo(const std::function<void()>& func);
};