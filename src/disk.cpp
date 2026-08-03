#include <stdexcept>
#include <memory>
#include "disk.hpp"
#include "utilities.h"

#define BLOCK_SIZE 128

void DiskManager::verify_pre_header() {
    unsigned long long pre_header = 0;
    int count = 0;
    int ch;

    // seek pre-header start
    if (fseek(this->file, 0, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the pre-header location in the vault file.");

    while (count < PRE_HEADER_SIZE && (ch = fgetc(this->file)) != EOF) {
        unsigned char byte = (unsigned char)ch;
        pre_header <<= BYTE_SIZE;
        pre_header |= byte;
        count++;
    }

    if (pre_header != PRE_HEADER) throw std::runtime_error("Vault header doesn't match.");
}

void DiskManager::get_vault_size() {
    if (fseek(this->file, 0, SEEK_END) != 0) throw std::runtime_error("Faield to seek to end of the vault file");

    this->file_size = ftell(file);
    if (this->file_size == -1L) throw std::runtime_error("Faield to seek to end of the vault file");
}

void DiskManager::read_vault_header(Salt salt, SafeVar &master_key) {
    int encrypted_key_len = KEY_LEN + AUTH_TAG_LEN;

    // seek header start
    if (fseek(this->file, PRE_HEADER_SIZE, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    // read salt
    if (fread(salt, 1, SALT_LEN, this->file) != SALT_LEN) throw std::runtime_error("Failed to read the salt from the disk.");

    // read master key (encrypted)
    if (fread(master_key.get_ptr(true), 1, encrypted_key_len, this->file) != encrypted_key_len) throw std::runtime_error("Failed to read the master key from the disk.");
}

void DiskManager::write_vault_header(Salt salt, SafeVar &master_key) {
    int encrypted_key_len = KEY_LEN + AUTH_TAG_LEN;

    // seek header start
    if (fseek(this->file, PRE_HEADER_SIZE, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    // write salt
    if (fwrite(salt, 1, SALT_LEN, this->file) != SALT_LEN) throw std::runtime_error("Failed to write the salt to disk.");

    // write master key (encrypted)
    if (fwrite(master_key.get_ptr(true), 1, encrypted_key_len, this->file) != encrypted_key_len) throw std::runtime_error("Failed to write the master key to disk.");
}



void DiskManager::read_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key) {
    int read_len_name = MAX_NAME_LENGTH + AUTH_TAG_LEN;
    int read_len_pass = MAX_PASSWORD_LENGTH + AUTH_TAG_LEN;

    // seek  end of header
    if (fseek(this->file, PRE_HEADER_SIZE + HEADER_SIZE, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    while (true) {
        SafeVar name(MAX_NAME_LENGTH);
        SafeVar password(MAX_PASSWORD_LENGTH);

        // read the name
        if (fread(name.get_ptr(true), 1, read_len_name, this->file) != read_len_name) break;
        name.decrypt(master_key.get_ptr(false), false);

        // read the password
        if (fread(password.get_ptr(true), 1, read_len_pass, this->file) != read_len_pass) break;
        password.decrypt(master_key.get_ptr(false), false);
        password.encrypt(session_key.get_ptr(false));

        dict.append_node(std::move(name), std::move(password));
    }

    if (!feof(this->file)) throw std::runtime_error("Failed to read vault data.");
}

void DiskManager::write_vault_data(Dict &dict, SafeVar &master_key, SafeVar &session_key) {
    SafeVar name;
    SafeVar password;
    int read_len_name = MAX_NAME_LENGTH + AUTH_TAG_LEN;
    int read_len_pass = MAX_PASSWORD_LENGTH + AUTH_TAG_LEN;

    // seek  end of header
    if (fseek(this->file, PRE_HEADER_SIZE + HEADER_SIZE, SEEK_SET) != 0) throw std::runtime_error("Failed to seek the header location in the vault file.");

    for (Node *i = dict.get_head(); i != nullptr; i = (*i).get_next() ) {
        name = (*i).get_name();
        password = (*i).get_password();

        // read the name
        name.encrypt(master_key.get_ptr(false));
        if (fwrite(name.get_ptr(true), 1, read_len_name, this->file) != read_len_name) throw std::runtime_error("Failed to write vault data.");

        // read the password
        password.decrypt(session_key.get_ptr(false), false);
        password.encrypt(master_key.get_ptr(false));
        if (fwrite(password.get_ptr(true), 1, read_len_pass, this->file) != read_len_pass) throw std::runtime_error("Failed to write vault data.");
    }

    fflush(this->file);

    (*this).cut_file_size();
}

void DiskManager::cut_file_size() {
    return;
}