#pragma once

#include <exception>
#include "crypt.hpp"
#include "configs.hpp"
#include "dict.hpp"

namespace disk {

class Error : public config::GeneralError {
    public:
        using config::GeneralError::GeneralError;
};

enum ErrorCode {
    WriteError = 1,
    ReadError  = 2,
    SeekError = 3,
    TellError = 4,
    FlushError = 5,

    CreateError = 11,

    TruncateError = 21,

    WrongPreHeader = 31, 

    CurruptFile = 41
    
};

class DiskManager {
    private:
        FILE *file;


        static constexpr unsigned long long pre_header  = 0xDB1D26A4734EB42CLL;

        void verify_pre_header();
        void cut_file_size();
        void write_vault_pre_header() {
            if (!fwrite(&pre_header, sizeof(unsigned long long), 1, file)) throw Error("Couldn't write pre-header to disk.", WriteError);
        }

    public:
        static constexpr int pre_header_size = 8;
        static constexpr int header_size = crypto::salt_len + crypto::SafeVar::nonce_len + crypto::key_len + crypto::SafeVar::auth_tag_len;

        DiskManager() {
            int create = 0;

            file = fopen(config::vault_path, "rb+");
            if (file == nullptr) create = 1;

            if (create) {
                file = fopen(config::vault_path, "wb+");
                if (file == nullptr) throw Error("Failed to found and create Vault file.", CreateError);
                write_vault_pre_header();
            }
            else verify_pre_header();
        }

        ~DiskManager() {
            if (file != nullptr) fclose(file);
        }

        DiskManager(const DiskManager& other) = delete;
        DiskManager& operator=(const DiskManager& other) = delete;
        DiskManager(DiskManager&& other) = delete;
        DiskManager& operator=(DiskManager&& other) = delete;

        long long get_size();

        void read_vault_header(crypto::Salt salt, crypto::SafeVar &master_key);

        void write_vault_header(crypto::Salt salt, crypto::SafeVar &master_key);

        void read_vault_data(Dict &dict, crypto::SafeVar &master_key, crypto::SafeVar &session_key);

        void write_vault_data(Dict &dict, crypto::SafeVar &master_key, crypto::SafeVar &session_key);
};

}