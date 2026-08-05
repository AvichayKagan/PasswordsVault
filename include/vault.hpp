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
    
    public:

    Vault(SafeVar *password = nullptr) :master_key(KEY_LEN), session_key(KEY_LEN), disk_mang(password) {
        this->disk_mang.read_vault_header(this->salt, this->master_key);
    }

    void open_vault();

    void lock_vault() { this->dictionary.empty(); is_open = false; };

    void sudo(const std::function<void()>& func);
};