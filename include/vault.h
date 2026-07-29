#ifndef VAULT_H
#define VAULT_H

#include <string.h>
#include "disk.h"
#include "configs.h"
#include "dictionary.h"



typedef struct VaultContext {
    char *password;
    Data buffer;
    Key *password_hash;
    VaultHeader header;
    Key *session_key;
    Dict *dictionary;
    FILE *vault_file;
    char vault_file_dir[MAX_DIR_LENGTH]; // needed?
} VaultContext;

int open_vault(VaultContext* vault);

void lock_vault(VaultContext* vault);

int unlock_master_key(VaultContext *vault);

int search_vault(VaultContext *vault);

int init_dict(VaultContext *vault, Data *data);

int load_vault(VaultContext *vault);


#endif /* VAULT_H */