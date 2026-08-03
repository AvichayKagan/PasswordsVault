#pragma once


#include <cstring>
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
    
    public:

    Vault(int create) :master_key(KEY_LEN), session_key(KEY_LEN), disk_mang(VAULT_PATH, create) {}

    void open_vault();

    void lock_vault();

    void sudo(const std::function<void()>& func);
};