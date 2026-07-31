#include "disk.hpp"
#include "utilities.h"


int verify_pre_header(FILE* vault_file) {
    unsigned long long pre_header = 0;
    int count = 0;
    int ch;
    while (count < PRE_HEADER_SIZE && (ch = fgetc(vault_file)) != EOF) {
        unsigned char byte = (unsigned char)ch;
        pre_header <<= BYTE_SIZE;
        pre_header |= byte;
        count++;
    }

    return (pre_header == PRE_HEADER);
}


int read_vault_header(FILE* vault_file, VaultHeader *header) {
    int encrypted_key_len = crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_ABYTES;

    // seek header start
    if (fseek(vault_file, PRE_HEADER_SIZE, SEEK_SET) != 0) {
        fprintf(stderr, "Fatal Error: Failed to seek to header location in the vault file.\n");
        return -1;
    }

    // read salt
    if (fread(header->salt, 1, crypto_pwhash_SALTBYTES, vault_file) != crypto_pwhash_SALTBYTES) {
        fprintf(stderr, "Fatal Error: Failed to read salt from vault header.\n");
        return -1;
    }

    // read npub
    if (fread(header->master_key.npub, 1, crypto_aead_aes256gcm_NPUBBYTES, vault_file) != crypto_aead_aes256gcm_NPUBBYTES) {
        fprintf(stderr, "Fatal Error: Failed to read npub from vault header.\n");
        return -1;
    }

    header->master_key.data = sodium_malloc(encrypted_key_len);
    if (header->master_key.data == NULL) {
        fprintf(stderr, "Fatal Error: Failed to allocate memory for the master key.\n");
        return -1;
    }
    // read master key (encrypted)
    if (fread(header->master_key.data, 1, encrypted_key_len, vault_file) != encrypted_key_len) {
        fprintf(stderr, "Fatal Error: Failed to read master key from vault header.\n");
        sodium_free(header->master_key.data);
        return -1;
    }

    // set the master key encrytped length
    header->master_key.len = encrypted_key_len;

    return 0;
}

int write_vault_header(FILE* vault_file, VaultHeader *header) {
    int encrypted_key_len = crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_ABYTES;
    unsigned char pre_header[PRE_HEADER_SIZE];
    unsigned long long pre_header_ll = PRE_HEADER;

    // load the pre-header to array
    for (int i = PRE_HEADER_SIZE - 1; i >= 0; i--) {
        pre_header[i] = (unsigned char)pre_header_ll;
        pre_header_ll >>= BYTE_SIZE;
    }

    // seek  start
    if (fseek(vault_file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Fatal Error: Failed to seek to start of the vault file.\n");
        return -1;
    }

    // write pre header
    if (fwrite(pre_header, 1, PRE_HEADER_SIZE, vault_file) != PRE_HEADER_SIZE) {
        fprintf(stderr, "Fatal Error: Failed to write pre header to vault.\n");
        return -1;
    }

    // write salt
    if (fwrite(header->salt, 1, crypto_pwhash_SALTBYTES, vault_file) != crypto_pwhash_SALTBYTES) {
        fprintf(stderr, "Fatal Error: Failed to write salt to vault header.\n");
        return -1;
    }

    // write npub
    if (fwrite(header->master_key.npub, 1, crypto_aead_aes256gcm_NPUBBYTES, vault_file) != crypto_aead_aes256gcm_NPUBBYTES) {
        fprintf(stderr, "Fatal Error: Failed to write npub to vault header.\n");
        return -1;
    }

    // write master key (encrypted)
    if (fwrite(header->master_key.data, 1, encrypted_key_len, vault_file) != encrypted_key_len) {
        fprintf(stderr, "Fatal Error: Failed to write master key to vault header.\n");
        return -1;
    }

    return 0;
}

int write_vault_data(FILE* vault_file, Data *data) {
    // seek  end of header
    if (fseek(vault_file, PRE_HEADER_SIZE + HEADER_SIZE, SEEK_SET) != 0) {
        fprintf(stderr, "Fatal Error: Failed to seek to start of the vault file.\n");
        return -1;
    }

    // write data npub
    if (fwrite(data->npub, 1, crypto_aead_aes256gcm_NPUBBYTES, vault_file) != crypto_aead_aes256gcm_NPUBBYTES) {
        fprintf(stderr, "Fatal Error: Failed to write data npub to vault.\n");
        return -1;
    }

    // write encrypted data
    if (fwrite(data->data, 1, data->len, vault_file) != data->len) {
        fprintf(stderr, "Fatal Error: Failed to write data to vault.\n");
        return -1;
    }

    return 0;
}

int read_vault_data(Data *buffer, FILE* vault_file) {
    // seek  end of header
    if (fseek(vault_file, PRE_HEADER_SIZE + HEADER_SIZE, SEEK_SET) != 0) {
        fprintf(stderr, "Fatal Error: Failed to seek to start of the vault file.\n");
        return -1;
    }

    // read data npub
    if (fread(buffer->npub, 1, crypto_aead_aes256gcm_NPUBBYTES, vault_file) != crypto_aead_aes256gcm_NPUBBYTES) {
        fprintf(stderr, "Fatal Error: Failed to read data npub from vault header.\n");
        return -1;
    }

    return load_file_to_buffer(vault_file, buffer, HEADER_SIZE + PRE_HEADER_SIZE + crypto_aead_aes256gcm_NPUBBYTES);
}