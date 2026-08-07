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
        Salt salt;
        SafeVar master_key;
        SafeVar session_key;
        Dict dictionary;
        DiskManager disk_mang;
        bool is_open = false;


        void init_vault();
    
    public:

    Vault() :master_key(KEY_LEN), session_key(KEY_LEN) {
        if (disk_mang.get_size() == PRE_HEADER_SIZE) init_vault();

        disk_mang.read_vault_header(this->salt, this->master_key);
    }

    void open_vault();

    void lock_vault() { this->dictionary.empty(); is_open = false; };

    void sudo(const std::function<void()>& func);
};