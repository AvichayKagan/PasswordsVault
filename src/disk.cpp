#include <stdexcept>
#include <memory>
#include "disk.hpp"

#define PRE_HEADER 0xDB1D26A4734EB42CLL
#define PRE_HEADER_SIZE 8 // in bytes
#define HEADER_SIZE (SALT_LEN + NONCE_LEN + KEY_LEN + AUTH_TAG_LEN)
#define BYTE_SIZE 8 // in bits


// for truncating the file on each operating system
#ifdef _WIN32
    #include <io.h>
    #define TRUNCATE_FILE(fd, size) _chsize_s((fd), (size))
    #define FILENO(fp) _fileno(fp)
#else
    #include <unistd.h>
    #define TRUNCATE_FILE(fd, size) ftruncate((fd), (size))
    #define FILENO(fp) fileno(fp)
#endif

void DiskManager::verify_pre_header() {
    unsigned long long pre_header;
    size_t read_count = fread(&pre_header, sizeof(unsigned long long), 1, file);

    if (read_count != 1 || pre_header != PRE_HEADER_SIZE) throw std::runtime_error("Vault header doesn't match.");
}

void DiskManager::get_vault_size() {
    if (fseek(file, 0, SEEK_END) != 0) throw std::runtime_error("Faield to seek to end of the vault file");

    file_size = ftell(file);
    if (file_size == -1L) throw std::runtime_error("Faield to seek to end of the vault file");
}

void DiskManager::read_vault_header(Salt salt, SafeVar &master_key) {
    size_t encrypted_key_len = KEY_LEN + AUTH_TAG_LEN;

    // seek header start
    if (fseek(file, PRE_HEADER_SIZE, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    // read salt
    if (fread(salt, 1, SALT_LEN, file) != SALT_LEN) throw std::runtime_error("Failed to read the salt from the disk.");

    // read master key (encrypted)
    if (fread(master_key.get_ptr(true), 1, encrypted_key_len, file) != encrypted_key_len) throw std::runtime_error("Failed to read the master key from the disk.");
}

void DiskManager::write_vault_header(Salt salt, SafeVar &master_key) {
    size_t encrypted_key_len = KEY_LEN + ENCRYPTION_BUFF_LEN;

    // seek header start
    if (fseek(file, PRE_HEADER_SIZE, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    // write salt
    if (fwrite(salt, 1, SALT_LEN, file) != SALT_LEN) throw std::runtime_error("Failed to write the salt to disk.");

    // write master key (encrypted)
    if (fwrite(master_key.get_ptr(true), 1, encrypted_key_len, file) != encrypted_key_len) throw std::runtime_error("Failed to write the master key to disk.");
}



void DiskManager::read_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key) {
    size_t read_len_name = MAX_NAME_LENGTH + AUTH_TAG_LEN;
    size_t read_len_pass = MAX_PASSWORD_LENGTH + AUTH_TAG_LEN;

    // seek  end of header
    if (fseek(file, PRE_HEADER_SIZE + HEADER_SIZE, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    while (true) {
        SafeVar name(MAX_NAME_LENGTH);
        SafeVar password(MAX_PASSWORD_LENGTH);

        // read the name
        if (fread(name.get_ptr(true), 1, read_len_name, file) != read_len_name) break;
        name.decrypt(master_key.get_ptr(false), false);

        // read the password
        if (fread(password.get_ptr(true), 1, read_len_pass, file) != read_len_pass) break;
        password.decrypt(master_key.get_ptr(false), false);
        password.encrypt(session_key.get_ptr(false));

        dict.append_node(std::move(name), std::move(password));
    }

    if (!feof(file)) throw std::runtime_error("Failed to read vault data.");
}

void DiskManager::write_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key) {
    SafeVar name;
    SafeVar password;
    size_t read_len_name = MAX_NAME_LENGTH + AUTH_TAG_LEN;
    size_t read_len_pass = MAX_PASSWORD_LENGTH + AUTH_TAG_LEN;

    // seek  end of header
    if (fseek(file, PRE_HEADER_SIZE + HEADER_SIZE, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    for (Node *i = dict.get_head(); i != nullptr; i = i->get_next() ) {
        name = i->get_name();
        password = i->get_password();

        // read the name
        name.encrypt(master_key.get_ptr(false));
        if (fwrite(name.get_ptr(true), 1, read_len_name, file) != read_len_name) throw std::runtime_error("Failed to write vault data.");

        // read the password
        password.decrypt(session_key.get_ptr(false), false);
        password.encrypt(master_key.get_ptr(false));
        if (fwrite(password.get_ptr(true), 1, read_len_pass, file) != read_len_pass) throw std::runtime_error("Failed to write vault data.");
    }

    (*this).cut_file_size();
}

void DiskManager::cut_file_size() {
    if (fflush(file) != 0) throw std::runtime_error("Failed to flush vault data.");

    long current_pos = ftell(file);
    if (current_pos == -1L) throw std::runtime_error("Failed to get current file position.");

    int fd = FILENO(file);
    if (fd == -1) throw std::runtime_error("Failed to get file descriptor.");

    if (TRUNCATE_FILE(fd, current_pos) != 0) throw std::runtime_error("Failed to truncate file size.");
}



void DiskManager::init_vault(SafeVar &password) {
    unsigned long long pre_header = PRE_HEADER;
    SafeVar salt(SALT_LEN);
    SafeVar master_key(KEY_LEN);

    salt.random();
    master_key.random().encrypt(password.get_ptr(false));

    // write the pre-header
    if (!fwrite(&pre_header, sizeof(unsigned long long), 1, file)) throw std::runtime_error("Couldn't write pre-header to disk.");

    // write hte header - salt and master key
    write_vault_header(salt.get_ptr(false), master_key);
}