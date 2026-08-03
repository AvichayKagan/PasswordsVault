#pragma once

#include <exception>
#include "crypt.hpp"
#include "configs.hpp"
#include "dict.hpp"

#define PRE_HEADER 0xDB1D26A4734EB42CLL
#define PRE_HEADER_SIZE 8 // in bytes
#define HEADER_SIZE (SALT_LEN + NONCE_LEN + KEY_LEN + AUTH_TAG_LEN)
#define BYTE_SIZE 8 // in bits


class DiskManager {
    private:
        FILE *file;
        long file_size;

        void verify_pre_header();
        void get_vault_size();
        void cut_file_size();

    public:
        DiskManager(const char *path, int create) {
            int pre_header;
            const char *mode[2] = {"rb+", "wb+"};

            file = fopen(VAULT_PATH, mode[create]);
            if (file == nullptr) {
                if (create) throw std::runtime_error("Faield to create Vault file.");
                throw std::runtime_error("Vault file wasn't found.");
            }

            verify_pre_header();
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

