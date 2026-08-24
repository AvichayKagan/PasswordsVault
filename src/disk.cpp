#include <stdexcept>
#include <memory>
#include <iostream>
#include <thread>
#include <chrono>
#include "disk.hpp"

using namespace disk;

#ifdef _WIN32
    // --- WINDOWS ---
    #include <windows.h>
    #include <io.h>

    int os_flush(FILE* file) {
        int fd = _fileno(file);
        if (fd == -1) return -1;
        HANDLE hFile = (HANDLE)_get_osfhandle(fd);
        if (hFile == INVALID_HANDLE_VALUE) return -1;
        return (FlushFileBuffers(hFile) == 0) ? -1 : 0;
    }

#elif defined(__APPLE__)
    // --- MACOS ---
    #include <unistd.h>
    #include <fcntl.h>
    #include <cerrno>

    int os_flush(FILE* file) {
        int fd = fileno(file);
        if (fd == -1) return -1;
        if (fcntl(fd, F_FULLFSYNC, 0) == -1) {
            // fallback if the drive doesn't support F_FULLFSYNC
            if (errno == ENOTSUP) return fsync(fd);
            return -1;
        }
        return 0;
    }

#else
    // --- LINUX / POSIX ---
    #include <unistd.h>

    int os_flush(FILE* file) {
        int fd = fileno(file);
        if (fd == -1) return -1;
        return fsync(fd);
    }

#endif


void DiskManager::verify_pre_header() { // here we assume little endian, for portabilit change this in the future
    unsigned long long pre_header_read;
    size_t read_count = fread(&pre_header_read, sizeof(unsigned long long), 1, file);

    if (read_count != 1 || pre_header_read != pre_header) throw Error("Vault header doesn't match.", WrongPreHeader);
}


long long DiskManager::get_size() {
    if (fseek(file, 0, SEEK_END) != 0) throw Error("Failed to seek to end of the vault file", SeekError);

    int file_size = ftell(file);
    if (file_size == -1L) throw Error("Failed to seek to end of the vault file", TellError);

    return file_size;
}

void DiskManager::read_vault_header(crypto::Salt salt, crypto::SafeVar &master_key) {
    size_t encryptoed_key_len = crypto::key_len + crypto::SafeVar::encryptoion_buff_len;

    // seek header start
    if (fseek(file, pre_header_size, SEEK_SET) != 0) throw Error("Failed to seek the header location in the vault file.", SeekError);

    // read salt
    if (fread(salt, 1, crypto::salt_len, file) != crypto::salt_len) throw Error("Failed to read the salt from the disk.", ReadError);

    // read master key (encryptoed)
    if (fread(master_key.get(), 1, encryptoed_key_len, file) != encryptoed_key_len) throw Error("Failed to read the master key from the disk.", ReadError);
}


void DiskManager::read_vault_data(Dict &dict, crypto::SafeVar &master_key, crypto::SafeVar &session_key) {
    size_t read_len = this->get_size() - pre_header_size - header_size;
    crypto::SafeVar vault_data(read_len - crypto::SafeVar::encryptoion_buff_len);
    size_t i = 0;

    // read the data to buffer and decrypt
    if (fseek(file, pre_plus_header_size, SEEK_SET) != 0) throw Error("Failed to seek the header location in the vault file.", SeekError);
    if (fread(vault_data.get(), 1, read_len, file) != read_len) throw Error("Failed to read vault data.", ReadError);
    vault_data.decrypto(master_key.get(), false);

    // load the dictionary
    while (i < read_len - crypto::SafeVar::encryptoion_buff_len) {
        crypto::SafeVar name(config::max_name_len);
        crypto::SafeVar password(config::max_password_len);

        // set the name
        std::memcpy(name.get(), vault_data.get() + i, config::max_name_len);
        i += config::max_name_len;

        // set the password
        std::memcpy(password.get(), vault_data.get() + i, config::max_password_len);
        password.encrypto(session_key.get());
        i += config::max_password_len;

        dict.append_node(std::move(name), std::move(password));
    }
}


void DiskManager::atomic_write_file(Dict &dict, crypto::SafeVar &master_key, crypto::SafeVar &master_key_enc, crypto::SafeVar &session_key, crypto::Salt salt) {
    crypto::SafeVar vault_data = dict.pack(session_key, master_key);
    FILE *temp = fopen(config::vault_path_temp, "wb+");
    if (temp == nullptr) throw Error("Failed to create the temp vault file.", CreateError);

    bool renamed = false;
    try {
        // write pre header
        if (!fwrite(&pre_header, sizeof(unsigned long long), 1, temp)) throw Error("Couldn't write pre-header to temp file.", WriteError);

        // write salt
        if (fwrite(salt, 1, crypto::salt_len, temp) != crypto::salt_len) throw Error("Failed to write the salt to temp file.", WriteError);

        // write master key (encryptoed)
        if (fwrite(master_key_enc.get(), 1, master_key_enc.get_size(), temp) != master_key_enc.get_size()) throw Error("Failed to write the master key to temp file.", WriteError);

        // write data to temp file
        if (fwrite(vault_data.get(), 1, vault_data.get_size(), temp) != vault_data.get_size()) throw Error("Failed to write vault data to temp file.", WriteError);

        // flush the temp
        if (fflush(temp) != 0) throw Error("Failed to fflush vault data.", FlushError);
        if (os_flush(temp) != 0) throw Error("Failed to OS flush vault data.", FlushError);

        // close the files
        fclose(file);
        file = nullptr;
        fclose(temp);
        temp = nullptr;

        // rename & swap
        std::error_code ec;
        for (int i = 0; i < 5; i++) {
            std::filesystem::rename(config::vault_path_temp, config::vault_path, ec);
            if (!ec) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (ec) throw Error("Failed swap temp with file with vault file.", RenameError);
        renamed = true;

        // re-open the file
        for (int i = 0; i < 5; i++) {
            file = fopen(config::vault_path, "rb+");
            if (file != nullptr) return;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        throw config::FatalError("Failed re-open the vault post atomic renmae.", "DISK", OpenError);
    }
    catch (...) {
        if (temp != nullptr) fclose(temp);
        if (!renamed) {
            std::error_code ec;
            for (int i = 0; i < 5; i++) {
                std::filesystem::remove(config::vault_path_temp, ec);
                if (!ec) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            if (ec) std::cerr << "WARNING: Failed to clean up temp file: " << config::vault_path_temp << ": " << ec.message() << "\n";
        }
        throw;
    }
}