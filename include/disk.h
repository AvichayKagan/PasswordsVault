#ifndef DISK_H
#define DISK_H

#include "encryption.h"

#define PRE_HEADER 0xDB1D26A4734EB42CLL
#define PRE_HEADER_SIZE 8 // in bytes
#define HEADER_SIZE (crypto_pwhash_SALTBYTES + crypto_aead_aes256gcm_NPUBBYTES + crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_ABYTES)
#define BYTE_SIZE 8 // in bits

typedef struct VaultHeader {
    Data master_key;
    Salt salt;
} VaultHeader;

int verify_pre_header(FILE* vault_file);

int read_vault_header(FILE* vault_file, VaultHeader *header);

int write_vault_header(FILE* vault_file, VaultHeader *header);

int write_vault_data(FILE* vault_file, Data *data);

int load_buffer(Data *buffer, FILE* vault_file);


#endif /* DISK_H */