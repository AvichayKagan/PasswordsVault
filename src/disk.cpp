#include <stdexcept>
#include <memory>
#include <iostream>
#include "disk.hpp"

using namespace disk;

// for truncating the file on each operating system
#ifdef _WIN32
    #include <io.h>
    #include <stdio.h>

    inline void truncate_file(FILE * file, unsigned long long pos) {
        int fd = _fileno(file);
        if (fd == -1) throw Error("Failed to get file descriptor.", TruncateError);

        if (_chsize_s(fd, pos) != 0) throw Error("Failed to truncate file size.", TruncateError);
    }
#else
    #include <unistd.h>
    #include <stdio.h>

    inline void truncate_file(FILE * file, unsigned long long pos) {
        int fd = fileno(file);
        if (fd == -1) throw Error("Failed to get file descriptor.", TruncateError);

        if (ftruncate(fd, pos) != 0) throw Error("Failed to truncate file size.", TruncateError);
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

void DiskManager::write_vault_header(crypto::Salt salt, crypto::SafeVar &master_key) {
    size_t encryptoed_key_len = crypto::key_len + crypto::SafeVar::encryptoion_buff_len;

    // seek header start
    if (fseek(file, pre_header_size, SEEK_SET) != 0) throw Error("Failed to seek the header location in the vault file.", SeekError);

    // write salt
    if (fwrite(salt, 1, crypto::salt_len, file) != crypto::salt_len) throw Error("Failed to write the salt to disk.", WriteError);

    // write master key (encryptoed)
    if (fwrite(master_key.get(), 1, encryptoed_key_len, file) != encryptoed_key_len) throw Error("Failed to write the master key to disk.", WriteError);
}



void DiskManager::read_vault_data(Dict &dict, crypto::SafeVar &master_key, crypto::SafeVar &session_key) {
    size_t read_len = this->get_size() - pre_header_size - header_size;
    crypto::SafeVar vault_data(read_len - crypto::SafeVar::encryptoion_buff_len);
    size_t i = 0;

    // read the data to buffer and decrypt
    if (fseek(file, pre_header_size + header_size, SEEK_SET) != 0) throw Error("Failed to seek the header location in the vault file.", SeekError);
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

void DiskManager::write_vault_data(Dict &dict, crypto::SafeVar &master_key, crypto::SafeVar &session_key) { // need to ahndle failure and disk corruption
    size_t write_len = dict.get_count() * (config::max_name_len + config::max_password_len);
    crypto::SafeVar vault_data(write_len);
    int j = 0;
    
    // load the buffer
    for (Dict::Node *i = dict.get_head(); i != nullptr; i = i->get_next()) {
        crypto::SafeVar& password = i->get_password();

        // write the name
        std::memcpy(vault_data.get() + j, i->get_name().get(), config::max_name_len);
        j += config::max_name_len;

        // write the password
        password.decrypto(session_key.get(), false);
        std::memcpy(vault_data.get() + j, password.get(), config::max_password_len);
        j += config::max_password_len;
        password.encrypto(session_key.get());
    }
    vault_data.encrypto(master_key.get());

    // write the data
    if (fseek(file, pre_header_size + header_size, SEEK_SET) != 0) throw Error("Failed to seek the header location in the vault file.", SeekError);
    if (fwrite(vault_data.get(), 1, write_len + crypto::SafeVar::encryptoion_buff_len, file) != write_len + crypto::SafeVar::encryptoion_buff_len) throw Error("Failed to write vault data.", WriteError);
    
    this->cut_file_size();
}

void DiskManager::cut_file_size() {
    if (fflush(file) != 0) throw Error("Failed to flush vault data.", FlushError);

    long long current_pos = ftell(file);
    if (current_pos == -1L) throw Error("Failed to get current file position.", TellError);

    truncate_file(file, current_pos);
}