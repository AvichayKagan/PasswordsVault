#pragma once

#include <exception>
#include "crypt.hpp"
#include "configs.hpp"
#include "dict.hpp"




class DiskManager {
    private:
        FILE *file;
        long file_size;

        void verify_pre_header();
        void get_vault_size();
        void cut_file_size();
        void init_vault(SafeVar &password);

    public:
        DiskManager(SafeVar *password = nullptr) {
            const char *mode[2] = {"rb+", "wb+"};
            int create = (password == nullptr ? 0 : 1);

            file = fopen(VAULT_PATH, mode[create]);
            if (file == nullptr) {
                if (create) throw std::runtime_error("Failed to create Vault file.");
                throw std::runtime_error("Vault file wasn't found.");
            }

            if (create) {
                init_vault(*password);
            }
            else verify_pre_header();

            get_vault_size();
        }

        ~DiskManager() {
            if (file != nullptr) fclose(file);
        }

        DiskManager(const DiskManager& other) = delete;
        DiskManager& operator=(const DiskManager& other) = delete;
        DiskManager(DiskManager&& other) = delete;
        DiskManager& operator=(DiskManager&& other) = delete;


        void read_vault_header(Salt salt, SafeVar &master_key);

        void write_vault_header(Salt salt, SafeVar &master_key);

        void read_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key);

        void write_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key);
};

