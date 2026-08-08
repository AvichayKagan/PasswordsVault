#pragma once

#include <exception>
#include "crypt.hpp"
#include "configs.hpp"
#include "dict.hpp"


class DiskManager {
    private:
        FILE *file;
        long long file_size;


        static constexpr unsigned long long pre_header  = 0xDB1D26A4734EB42CLL;
        static constexpr int header_size = crypto::salt_len + crypto::SafeVar::nonce_len + crypto::key_len + crypto::SafeVar::auth_tag_len;

        void verify_pre_header();
        void get_vault_size();
        void cut_file_size();
        void write_vault_pre_header() {
            if (!fwrite(&pre_header, sizeof(unsigned long long), 1, file)) throw std::runtime_error("Couldn't write pre-header to disk.");
        }

    public:
        static constexpr int pre_header_size = 8;

        DiskManager() {
            int create = 0;

            file = fopen(config::vault_path, "rb+");
            if (file == nullptr) create = 1;

            if (create) {
                file = fopen(config::vault_path, "wb+");
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

        void read_vault_header(crypto::Salt salt, crypto::SafeVar &master_key);

        void write_vault_header(crypto::Salt salt, crypto::SafeVar &master_key);

        void read_vault_data(Dict &dict, crypto::SafeVar &master_key, crypto::SafeVar &session_key);

        void write_vault_data(Dict &dict, crypto::SafeVar &master_key, crypto::SafeVar &session_key);
};