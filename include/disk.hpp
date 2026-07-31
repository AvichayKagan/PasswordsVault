#pragma once


#include <stdexcept>
#include "crypt.hpp"

#define PRE_HEADER 0xDB1D26A4734EB42CLL
#define PRE_HEADER_SIZE 8 // in bytes
#define HEADER_SIZE (SALT_LEN + NONCE_LEN + KEY_LEN + AUTH_TAG_LEN)
#define BYTE_SIZE 8 // in bits


int verify_pre_header(FILE* vault_file);

int read_vault_header(FILE* vault_file, Salt salt, SafeVar &master_key);

int write_vault_header(FILE* vault_file, Salt salt, SafeVar &master_key);

int write_vault_data(FILE* vault_file, SafeVar &buffer);

int read_vault_data(FILE* vault_file, SafeVar &buffer);