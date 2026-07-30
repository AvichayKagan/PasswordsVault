#include <string.h>
#include "encryption.hpp"



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


void SafeVar::encrypt(Key key) {
    randombytes_buf(this->ptr, NONCE_LEN); // generate the nounce

    crypto_aead_aes256gcm_encrypt(
        this->ptr + NONCE_LEN, // write inplace the encrypted data to data
        (unsigned long long *)&this->len, // update the length
        this->ptr + NONCE_LEN, this->len, // unencrypted data and its length
        NULL, 0, NULL, 
        this->ptr, key // nounce and key
    );
}

int SafeVar::decrypt(Key key, bool no_corrupt) {
    SafeVar backup = *this;

    int error = crypto_aead_aes256gcm_decrypt(
        this->ptr + NONCE_LEN, // write inplace the decrypted data to data
        (unsigned long long *)&this->len, // update the length
        NULL,
        this->ptr + NONCE_LEN, this->len, // encrypted data data and its length
        NULL, 0,
        this->ptr, key // nounce and key
    );

    if (error && no_corrupt) *this = std::move(backup);

    return error;
}


int SafeVar::hash(SafeVar& dest, Salt salt) {
    int error = crypto_pwhash(
        dest,
        KEY_LEN,
        (char *)this->ptr + NONCE_LEN,
        this->len,
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13
    );

    return error;
}