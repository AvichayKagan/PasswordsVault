#include <stdexcept>
#include <memory>
#include "disk.hpp"

using namespace crypto;

// for truncating the file on each operating system
#ifdef _WIN32
    #include <io.h>
    #include <stdio.h>

    inline void truncate_file(FILE * file, unsigned long long pos) {
        int fd = _fileno(file);
        if (fd == -1) throw std::runtime_error("Failed to get file descriptor.");

        if (_chsize_s(fd, pos) != 0) throw std::runtime_error("Failed to truncate file size.");
    }
#else
    #include <unistd.h>
    #include <stdio.h>

    inline void truncate_file(FILE * file, unsigned long long pos) {
        int fd = fileno(file);
        if (fd == -1) throw std::runtime_error("Failed to get file descriptor.");

        if (ftruncate(fd, pos) != 0) throw std::runtime_error("Failed to truncate file size.");
    }
#endif

void DiskManager::verify_pre_header() {
    unsigned long long pre_header_read;
    size_t read_count = fread(&pre_header_read, sizeof(unsigned long long), 1, file);

    if (read_count != 1 || pre_header_read != pre_header) throw std::runtime_error("Vault header doesn't match.");
}


void DiskManager::get_vault_size() {
    if (fseek(file, 0, SEEK_END) != 0) throw std::runtime_error("Faield to seek to end of the vault file");

    file_size = ftell(file);
    if (file_size == -1L) throw std::runtime_error("Faield to seek to end of the vault file");
}

void DiskManager::read_vault_header(Salt salt, SafeVar &master_key) {
    size_t encryptoed_key_len = key_len + SafeVar::encryptoion_buff_len;

    // seek header start
    if (fseek(file, pre_header_size, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    // read salt
    if (fread(salt, 1, salt_len, file) != salt_len) throw std::runtime_error("Failed to read the salt from the disk.");

    // read master key (encryptoed)
    if (fread(master_key.get(), 1, encryptoed_key_len, file) != encryptoed_key_len) throw std::runtime_error("Failed to read the master key from the disk.");
}

void DiskManager::write_vault_header(Salt salt, SafeVar &master_key) {
    size_t encryptoed_key_len = key_len + SafeVar::encryptoion_buff_len;

    // seek header start
    if (fseek(file, pre_header_size, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    // write salt
    if (fwrite(salt, 1, salt_len, file) != salt_len) throw std::runtime_error("Failed to write the salt to disk.");

    // write master key (encryptoed)
    if (fwrite(master_key.get(), 1, encryptoed_key_len, file) != encryptoed_key_len) throw std::runtime_error("Failed to write the master key to disk.");
}



void DiskManager::read_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key) {
    size_t read_len_name = config::max_name_len + SafeVar::auth_tag_len;
    size_t read_len_pass = config::max_password_len + SafeVar::auth_tag_len;

    // seek  end of header
    if (fseek(file, pre_header_size + header_size, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    while (true) {
        SafeVar name(config::max_name_len);
        SafeVar password(config::max_password_len);

        // read the name
        if (fread(name.get(), 1, read_len_name, file) != read_len_name) break;
        name.decrypto(master_key.get(), false);

        // read the password
        if (fread(password.get(), 1, read_len_pass, file) != read_len_pass) break;
        password.decrypto(master_key.get(), false);
        password.encrypto(session_key.get());

        dict.append_node(std::move(name), std::move(password));
    }

    if (!feof(file)) throw std::runtime_error("Failed to read vault data.");
}

void DiskManager::write_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key) {
    SafeVar name;
    SafeVar password;
    size_t read_len_name = config::max_name_len + SafeVar::auth_tag_len;
    size_t read_len_pass = config::max_password_len + SafeVar::auth_tag_len;

    // seek  end of header
    if (fseek(file, pre_header_size + header_size, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    for (Dict::Node *i = dict.get_head(); i != nullptr; i = i->get_next() ) {
        name = i->get_name();
        password = i->get_password();

        // read the name
        name.encrypto(master_key.get());
        if (fwrite(name.get(), 1, read_len_name, file) != read_len_name) throw std::runtime_error("Failed to write vault data.");

        // read the password
        password.decrypto(session_key.get(), false);
        password.encrypto(master_key.get());
        if (fwrite(password.get(), 1, read_len_pass, file) != read_len_pass) throw std::runtime_error("Failed to write vault data.");
    }

    (*this).cut_file_size();
}

void DiskManager::cut_file_size() {
    if (fflush(file) != 0) throw std::runtime_error("Failed to flush vault data.");

    long long current_pos = ftell(file);
    if (current_pos == -1L) throw std::runtime_error("Failed to get current file position.");

    truncate_file(file, current_pos);
}