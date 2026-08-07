#pragma once

#include <exception>
#include "crypt.hpp"
#include "configs.hpp"
#include "dict.hpp"


#define PRE_HEADER_SIZE 8 // in bytes


class DiskManager {
    private:
        FILE *file;
        long long file_size;

        void verify_pre_header();
        void get_vault_size();
        void cut_file_size();
        void write_vault_pre_header();

    public:
        DiskManager() {
            int create = 0;

            file = fopen(VAULT_PATH, "rb+");
            if (file == nullptr) create = 1;

            if (create) {
                file = fopen(VAULT_PATH, "wb+");
                if (file == nullptr) throw std::runtime_error("Failed to found and create Vault file.");
                write_vault_pre_header();
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

        long long get_size() { return file_size; };

        void read_vault_header(Salt salt, SafeVar &master_key);

        void write_vault_header(Salt salt, SafeVar &master_key);

        void read_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key);

        void write_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key);
};

