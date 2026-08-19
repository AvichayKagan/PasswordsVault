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

void DiskManager::verify_pre_header() {
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
    size_t read_len_name = config::max_name_len + crypto::SafeVar::encryptoion_buff_len;
    size_t read_len_pass = config::max_password_len + crypto::SafeVar::encryptoion_buff_len;

    // seek  end of header
    if (fseek(file, pre_header_size + header_size, SEEK_SET) != 0) throw Error("Failed to seek the header location in the vault file.", SeekError);

    while (true) {
        crypto::SafeVar name(config::max_name_len);
        crypto::SafeVar password(config::max_password_len);

        // read the name
        if (fread(name.get(), 1, read_len_name, file) != read_len_name) break;
        name.decrypto(master_key.get(), false);

        // read the password
        if (fread(password.get(), 1, read_len_pass, file) != read_len_pass) break;
        password.decrypto(master_key.get(), false);
        password.encrypto(session_key.get());

        dict.append_node(std::move(name), std::move(password));
    }

    if (!feof(file)) throw Error("Failed to read vault data.", CurruptFile);
}

void DiskManager::write_vault_data(Dict &dict, crypto::SafeVar &master_key, crypto::SafeVar &session_key) { // need to ahndle failure and disk corruption
    crypto::SafeVar name;
    crypto::SafeVar password;
    size_t read_len_name = config::max_name_len + crypto::SafeVar::encryptoion_buff_len;
    size_t read_len_pass = config::max_password_len + crypto::SafeVar::encryptoion_buff_len;

    // seek  end of header
    if (fseek(file, pre_header_size + header_size, SEEK_SET) != 0) throw Error("Failed to seek the header location in the vault file.", SeekError);
    
    for (Dict::Node *i = dict.get_head(); i != nullptr; i = i->get_next() ) {
        name = i->get_name();
        password = i->get_password();

        // write the name
        name.encrypto(master_key.get());
        if (fwrite(name.get(), 1, read_len_name, file) != read_len_name) throw Error("Failed to write vault data.", WriteError);

        // write the password
        password.decrypto(session_key.get(), false);
        password.encrypto(master_key.get());
        if (fwrite(password.get(), 1, read_len_pass, file) != read_len_pass) throw Error("Failed to write vault data.", WriteError);
    }
    
    this->cut_file_size();
}

void DiskManager::cut_file_size() {
    if (fflush(file) != 0) throw Error("Failed to flush vault data.", FlushError);

    long long current_pos = ftell(file);
    if (current_pos == -1L) throw Error("Failed to get current file position.", TellError);

    truncate_file(file, current_pos);
}