#include "utilities.h"
#include "vault.hpp"


void Vault::sudo(const std::function<void()>& func) { 
    SafeVar password;

    try {
        // init the passwrod
        password.hash(this->salt);
        (this->master_key).decrypt(password.get_ptr(), true);
        func();
    }
    catch (...) {
        (this->master_key).encrypt(password.get_ptr());
        password.memzero();
        throw;
    }

    (this->master_key).encrypt(password.get_ptr());
    password.memzero();
}

void Vault::open_vault() {
    // get vault size
    unsigned long long vault_size = get_vault_size(this->vault_file);
    if (vault_size < 0) throw std::runtime_error("Couldn't determine vault size.");

    // read vault data
    SafeVar data(vault_size - PRE_HEADER_SIZE - HEADER_SIZE);
    read_vault_data();

    // init vault header (salt and master key)
    if (read_vault_header(this->vault_file, this->salt, this->master_key)) throw std::runtime_error("Failed to read the vault header.");
    
    // init session key
    this->session_key.random(KEY_LEN);

    // decrypt the data
    (*this).sudo([&]() {
        data.decrypt(this->master_key.get_ptr(), false);
    });
    
    // init vault

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

int list_passwords(VaultContext *vault) {
    Node *curr = vault->dictionary.head;
    int n = 0;
    char *user_choice = sodium_malloc(MAX_NAME_LENGTH);

    if (curr == NULL) {
        printf("The vault is empty. no passwords are stored.");
        return 0;
    }

    while (curr != NULL) {
        printf("%d. %s", n, curr->name);
        n++;
        curr = curr->next;
    }

    printf("Please choose password to see (enter name):");
    while (1) {
        switch (read_string(user_choice, MAX_NAME_LENGTH)){
        case -1:
            fprintf(stderr, "Error: Could no take input from the terminal.\n");
            return -1;
        case 1:
            printf("Error: Invalid input, Please try again.\n");
            break;
        default:
            curr = search(&vault->dictionary, user_choice);
            if (curr == NULL) {
                printf("Error: Name does not exists, Please try again.\n");
                break;
            }
            sodium_free(user_choice);
            return show_password(vault, curr);
        }
    }

}

int show_password(VaultContext *vault, Node *node) {
    if (decrypt(&node->password, vault->session_key, 0)) {
        fprintf(stderr, "Fatal Error: Intrenal Memory corruption.\n");
        return -1;
    }
    
    printf("The password for %s is: %s. Press enter to delete this message.\n", node->name, node->password.data);
    encrypt(&node->password, vault->session_key);
    getchar();
    printf("\033[1A\033[2K"); //delte the message
    printf("The password for %s as been viewed.\n", node->name);

    return 0;
}

int change_password() {

}

int change_vault_password() {

}

int delete_password() {

}

int add_password(VaultContext *vault) {
    int loop = 1;
    char *name = sodium_malloc(MAX_NAME_LENGTH);
    Data password;
    Data password_dict;
    password.data = sodium_malloc(MAX_PASSWORD_LENGTH + crypto_aead_aes256gcm_ABYTES);
    password_dict.data = sodium_malloc(MAX_PASSWORD_LENGTH + crypto_aead_aes256gcm_ABYTES);

    printf("Please enter the name of the new service:\n");
    while (1) {
        switch (read_string(name, MAX_NAME_LENGTH)){
        case -1:
            fprintf(stderr, "Error: Could no take input from the terminal.\n");
            return -1;
        case 1:
            printf("Error: name can be at max %s chars, Please try again.\n", MAX_NAME_LENGTH - 1);
            break;
        default:
            loop = 0;
        }
    }

    loop = 1;
    printf("Please enter the password for the new service:\n");
    while (1) {
        switch (read_string(password.data, MAX_PASSWORD_LENGTH)){
        case -1:
            fprintf(stderr, "Error: Could no take input from the terminal.\n");
            return -1;
        case 1:
            printf("Error: name can be at max %s chars, Please try again.\n", MAX_NAME_LENGTH - 1);
            break;
        default:
            password.len = strlen(password.data) + 1;
            loop = 0;
        }
    }

    password_dict.len = password.len;
    memcpy(password_dict.data, password.data, MAX_PASSWORD_LENGTH);
    if (unlock_master_key(vault)) {
        sodium_free(password.data);
        sodium_free(password_dict.data);
        sodium_free(name);
        return -1;
    }

    
}

int search_password() {

}

