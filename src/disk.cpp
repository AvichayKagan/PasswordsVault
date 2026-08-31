#include <stdexcept>
#include <memory>
#include <iostream>
#include <thread>
#include <chrono>
#include "disk.hpp"

namespace {

template <typename T>
bool retry(T func, int times = 5, int delay = 10) {
    for (int i = 0; i < times; i++) {
        if (i != 0) std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        if (func()) return true;
    }
    return false;
}


#ifdef _WIN32
    // --- WINDOWS ---
    #include <windows.h>
    #include <io.h>

    int os_flush(FILE* file) {
        if (std::fflush(file)) return -1;
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
        if (std::fflush(file)) return -1;
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
        if (std::fflush(file)) return -1;
        int fd = fileno(file);
        if (fd == -1) return -1;
        return fsync(fd);
    }

#endif


} // anonymous namespace


namespace disk {


void DiskManager::verify_pre_header() { // here we assume little endian, for portabilit change this in the future
    unsigned long long pre_header_read;
    size_t read_count = std::fread(&pre_header_read, sizeof(unsigned long long), 1, file.get());

    if (read_count != 1 || pre_header_read != pre_header) throw Error("Vault header doesn't match.", WrongPreHeader);
}


long long DiskManager::get_size() {
    if (std::fseek(file.get(), 0, SEEK_END) != 0) throw Error("Failed to seek to end of the vault file", SeekError);

    int file_size = std::ftell(file.get());
    if (file_size == -1L) throw Error("Failed to seek to end of the vault file", TellError);

    return file_size;
}

void DiskManager::read_vault_header(crypto::Salt salt, crypto::SafeVar &master_key) {
    size_t encryptoed_key_len = crypto::key_len + crypto::SafeVar::encryptoion_buff_len;

    // seek header start
    if (std::fseek(file.get(), pre_header_size, SEEK_SET) != 0) throw Error("Failed to seek the header location in the vault file.", SeekError);

    // read salt
    if (std::fread(salt, 1, crypto::salt_len, file.get()) != crypto::salt_len) throw Error("Failed to read the salt from the disk.", ReadError);

    // read master key (encryptoed)
    if (std::fread(master_key.get(), 1, encryptoed_key_len, file.get()) != encryptoed_key_len) throw Error("Failed to read the master key from the disk.", ReadError);
}


crypto::SafeVar DiskManager::read_vault_data() {
    size_t read_len = this->get_size() - pre_header_size - header_size;
    crypto::SafeVar vault_data(read_len - crypto::SafeVar::encryptoion_buff_len);

    // read the data to buffer and decrypt
    if (std::fseek(file.get(), pre_plus_header_size, SEEK_SET) != 0) throw Error("Failed to seek the header location in the vault file.", SeekError);
    if (std::fread(vault_data.get(), 1, read_len, file.get()) != read_len) throw Error("Failed to read vault data.", ReadError);

    return vault_data;
}


void DiskManager::atomic_write_file(crypto::SafeVar &master_key_enc, crypto::Salt salt, crypto::SafeVar &data) {
    SafeFILE temp(std::fopen(config::vault_path_temp, "wb+"));
    if (temp == nullptr) throw Error("Failed to create the temp vault file.", CreateError);

    bool renamed = false;
    try {
        // write pre header
        if (!std::fwrite(&pre_header, sizeof(unsigned long long), 1, temp.get())) throw Error("Couldn't write pre-header to temp file.", WriteError);

        // write salt
        if (std::fwrite(salt, 1, crypto::salt_len, temp.get()) != crypto::salt_len) throw Error("Failed to write the salt to temp file.", WriteError);

        // write master key (encryptoed)
        if (std::fwrite(master_key_enc.get(), 1, master_key_enc.get_size(), temp.get()) != master_key_enc.get_size()) throw Error("Failed to write the master key to temp file.", WriteError);

        // write data to temp file
        if (std::fwrite(data.get(), 1, data.get_size(), temp.get()) != data.get_size()) throw Error("Failed to write vault data to temp file.", WriteError);

        // flush the temp
        if (os_flush(temp.get())) throw Error("Failed to OS flush vault data.", FlushError);

        // close the files
        file.reset();
        temp.reset();

        // rename & swap
        std::error_code ec;
        if (!retry([&]() {
            std::filesystem::rename(config::vault_path_temp, config::vault_path, ec);
            return !ec;
        })) throw Error("Failed swap temp with file with vault file: " + ec.message(), RenameError);
        renamed = true;

        // re-open the file
        if (!retry([&]() {
            file.reset(std::fopen(config::vault_path, "rb+"));
            return file != nullptr;
        })) throw config::FatalError("Failed re-open the vault post atomic renmae.", "DISK", OpenError);
    }
    catch (...) {
        temp.reset();
        if (!renamed) {
            std::error_code ec;
            if (!retry([&]() {
                std::filesystem::remove(config::vault_path_temp, ec);
                return !ec;
            })) std::cerr << "WARNING: Failed to clean up temp file: " << config::vault_path_temp << ": " << ec.message() << "\n";
        }
        throw;
    }
}

} // namespace disk