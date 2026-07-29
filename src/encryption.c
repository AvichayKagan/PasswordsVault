#include <string.h>
#include "encryption.h"

int crypto_init(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Fatal Error: Cryptographic sequence failed to initialized.\n");
        return -1;
    }

    if (!crypto_aead_aes256gcm_is_available()) {
        fprintf(stderr, "Fatal Error: CPU does not support AES hardware instructions.\n");
        return -1;
    }

    return 0;
}

void encrypt(Data* data, Key key) {
    randombytes_buf(data->npub, crypto_aead_aes256gcm_NPUBBYTES); // generate the npub

    crypto_aead_aes256gcm_encrypt(
        data->data, // write the encrypted data
        &data->len, // update the length
        data->data, data->len, // unencrypted data and its length
        NULL, 0, NULL, 
        data->npub, key // npub and key
    );
}

int decrypt(Data* data, Key key, int no_corrupt) {
    unsigned long long len = data->len;
    unsigned char *data_b;
    unsigned char npub[crypto_aead_aes256gcm_NPUBBYTES];

    if (no_corrupt) {
        data_b = sodium_malloc(len);
        memcpy(data_b, data->data, len);
        memcpy(npub, data->npub, crypto_aead_aes256gcm_NPUBBYTES);
    }

    int error = crypto_aead_aes256gcm_decrypt(
        data->data, &data->len, // the target for the decrypted data and its length
        NULL,
        data->data, // encrypted data address
        data->len, // encrypted data address length
        NULL, 0,
        data->npub, key // npub and key
    );

    if (error && no_corrupt) {
        memcpy(data->data, data_b, len);
        memcpy(data->npub, npub, crypto_aead_aes256gcm_NPUBBYTES);
        data->len = len;
    }

    if (no_corrupt) sodium_free(data_b);

    if (error) {
        if (!no_corrupt) fprintf(stderr, "Error: corrupted ciphertext!\n");
        return 1;
    }

    return 0;
}


int hash_password(char* password, unsigned char *dest, Salt salt) {
    int error = crypto_pwhash(
        dest,
        crypto_aead_aes256gcm_KEYBYTES,
        password,
        strlen(password),
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (error) {
        fprintf(stderr, "Fatal Error: Failed to Hash the password.\n");
        return -1;
    }

    return 0;
}