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
        FILE *vault_file;
    
    public:

    Vault(int create) {
        char *mode[2] = {"rb+", "wb+"};
        vault_file = fopen(VAULT_PATH, mode[create]);
        if (vault_file != nullptr) throw std::runtime_error("Vault file wasn't found.");
        if (verify_pre_header(vault_file)) throw std::runtime_error("Vault header doesn't match.");
    }

    ~Vault() { 
        fclose(vault_file);
    }

    Vault(const Vault& other) = delete;
    Vault& operator=(const Vault& other) = delete;
    Vault(Vault&& other) = delete;
    Vault& operator=(Vault&& other) = delete;

    void open_vault();

    void lock_vault();

    void sudo(const std::function<void()>& func)
};

int search_vault();

int load_vault();