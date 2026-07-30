#include "disk.h"
#include "utilities.h"
#include "vault.h"

#define DEFAULT_VAULT_PATH "vault.bin"
#define MAX_DIR_LENGTH 1024

int open_vault(VaultContext* vault) {

    // init the vault file
    load_vault(vault);

    // init vault header
    if (read_vault_header(vault->vault_file, &vault->header)) {
        fclose(vault->vault_file);
        return -1;
    }
    
    // init password hash, password and session key
    vault->password_hash = sodium_malloc(sizeof(Key));
    if (vault->password_hash == NULL) {
        fprintf(stderr, "Fatal Error: memery allocation failed.\n");
        fclose(vault->vault_file);
        sodium_free(vault->header.master_key.data);
        return -1;
    }
    vault->password = sodium_malloc(MAX_PASSWORD_LENGTH);
    if (vault->password == NULL) {
        fprintf(stderr, "Fatal Error: memery allocation failed.\n");
        fclose(vault->vault_file);
        sodium_free(vault->password_hash);
        sodium_free(vault->header.master_key.data);
        return -1;
    }
    vault->session_key = sodium_malloc(sizeof(Key));
    if (vault->session_key == NULL) {
        fclose(vault->vault_file);
        sodium_free(vault->password_hash);
        sodium_free(vault->password);
        sodium_free(vault->header.master_key.data);
        return -1;
    }
    randombytes_buf(vault->session_key, sizeof(Key)); // generate session key


    // init the vault_data
    if (read_vault_data(&vault->vault_data, vault->vault_file)) {
        fprintf(stderr, "Fatal Error: failed to load data to the buffer.\n");
        fclose(vault->vault_file);
        sodium_free(vault->password_hash);
        sodium_free(vault->password);
        sodium_free(vault->session_key);
        sodium_free(vault->header.master_key.data);
        return -1;
    }
    
    // unlock the master key
    if (unlock_master_key(vault)) {
        fclose(vault->vault_file);
        sodium_free(vault->password_hash);
        sodium_free(vault->password);
        sodium_free(vault->session_key);
        sodium_free(vault->vault_data.data);
        sodium_free(vault->header.master_key.data);
        return -1;
    }
    // HANDSHAKE, DESTROY MASTER KEY AND PASSWORD_HASH, HAND OVER CONTROL TO SESSION KEY
    decrypt(&vault->vault_data, vault->header.master_key.data, 0);
    encrypt(&vault->header.master_key, *vault->password_hash);
    sodium_memzero(vault->password_hash, sizeof(Key));

    // init the dictionary
    if (init_dict(vault, &vault->vault_data)) {
        fclose(vault->vault_file);
        sodium_free(vault->password_hash);
        sodium_free(vault->password);
        sodium_free(vault->session_key);
        sodium_free(vault->vault_data.data);
        sodium_free(vault->header.master_key.data);
        return -1;
    }

    return 0;
}

int unlock_master_key(VaultContext *vault) {
    printf("Please enter the vault password: ");
    while (1) {
        switch (read_string(vault->password, MAX_PASSWORD_LENGTH)) {
        case -1:
            fprintf(stderr, "Error: Could no take input from the terminal.\n");
            return -1;
        case 1:
            printf("Error: Incorrect passwrord, Please Try again:\n");
            continue;
        default:
            break;
        }
        if (hash_password(vault->password, *vault->password_hash, vault->header.salt)) return -1;
        sodium_memzero(vault->password, MAX_PASSWORD_LENGTH);
        if (!decrypt(&vault->header.master_key, *vault->password_hash, 1)) break;
        printf("Error: Incorrect passwrord, Please Try again:\n");
    }

    return 0;
}

int init_dict(VaultContext *vault, Data *data) {
    Data password_buffer;
    char *name;

    vault->dictionary.head = NULL;
    vault->dictionary.tail = NULL;

    for (int i = 0; i < data->len; i+=MAX_NAME_LENGTH + MAX_PASSWORD_LENGTH) {
        name = data->data + i;
        password_buffer.len = MAX_PASSWORD_LENGTH;
        password_buffer.data = name + MAX_NAME_LENGTH;
        encrypt(&password_buffer, *vault->session_key);
        if (append_node(&vault->dictionary, name, &password_buffer)) {
            fprintf(stderr, "Fatal Error: Memory allocation failed.\n");
            return -1;
        }
    }


    return 0;
}


void lock_vault(VaultContext* vault) {
    fclose(vault->vault_file);
    sodium_free(vault->password_hash);
    sodium_free(vault->password);
    sodium_free(vault->session_key);
    sodium_free(vault->vault_data.data);
    sodium_free(vault->header.master_key.data);
    empty_dict(&vault->dictionary);
}

int load_vault(VaultContext *vault) {
    vault->vault_file = fopen(DEFAULT_VAULT_PATH, "rb+");
    if (vault->vault_file == NULL || !verify_pre_header(vault->vault_file)) return search_vault(vault);
    return 0;
}

int create_vault(VaultContext *vault) {
    char *password = sodium_malloc(MAX_PASSWORD_LENGTH);
    unsigned char *password_hash = sodium_malloc(crypto_aead_aes256gcm_KEYBYTES);
    VaultHeader header;
    int error, loop = 1;
    unsigned char data[crypto_aead_aes256gcm_ABYTES];
    Data empty_vault = {data, 0, 0};

    randombytes_buf(header.salt, sizeof(Salt));
    header.master_key.len = crypto_aead_aes256gcm_KEYBYTES;
    header.master_key.data = sodium_malloc(crypto_aead_aes256gcm_KEYBYTES + crypto_aead_aes256gcm_ABYTES);

    vault->vault_file = fopen(DEFAULT_VAULT_PATH, "wb+");
    if (vault->vault_file == NULL) {
        perror("Fatal Error: Could not create vault file.");
        return -1;
    }

    printf("Please enter a password for the new vault:\n");
    while (loop) {
        switch (read_string(password, MAX_PASSWORD_LENGTH)){
            case -1:
                fprintf(stderr, "Error: Could no take input from the terminal.\n");
                return -1;
            case 1:
                printf("Error: Invalid input, max password length is %d, plese try again:\n", MAX_PASSWORD_LENGTH - 1);
                break;
            default:
                loop = 0;
                break;
        }
    }

    if (hash_password(password, password_hash, header.salt)) return -1;
    sodium_free(password);
    randombytes_buf(header.master_key.data, sizeof(Key)); // generate master key
    encrypt(&empty_vault, header.master_key.data);
    encrypt(&header.master_key, password_hash);
    sodium_free(password_hash);

    error = write_vault_header(vault->vault_file, &header);
    sodium_free(header.master_key.data);

    error |= write_vault_data(vault->vault_file, &empty_vault);

    if (!error) printf("Created a new vault at './vaukt.bin'!\n");
    
    return error;
}


int search_vault(VaultContext *vault) {
    char user_choice[2];
    int loop = 1;
    char vault_path[MAX_DIR_LENGTH];

    printf("Failed to open vault file, do you want to?\n");
    printf("\t1. Point to an existing vault file.\n");
    printf("\t2. Create a new vault.\n");
    printf("Enter you choise (1 or 2):\n");

    while (loop) {
        switch (read_string(user_choice, 2)){
        case -1:
            fprintf(stderr, "Error: Could no take input from the terminal.\n");
            return -1;
        case 1:
            printf("Error: Invalid input, please enter '1' or '2' mnnn:\n");
            break;
        default:
            switch (*user_choice){
                case '1':
                    loop = 0;
                    break;
                case '2':
                    return create_vault(vault);
                default:
                    printf("Error: Invalid input, please enter '1' or '2'.\n");
                    break;
            }
        }
    }


    printf("Enter the directory to the your vault file:\n");
    while (1) {
        switch (read_string(vault_path, MAX_DIR_LENGTH)){
        case -1:
            fprintf(stderr, "Error: Could no take input from the terminal.\n");
            return -1;
        case 1:
            printf("Error: Invalid input, max directory length is %d, plese try again:\n", MAX_DIR_LENGTH - 1);
            break;
        default:
            return load_vault(vault);
        }
    }
}

int list_passwords() {

}

int show_password() {

}

int change_password() {

}

int change_vault_password() {

}

int delete_password() {

}

int add_password() {

}

int search_password() {

}
