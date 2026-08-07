#include <iostream>
#include <stdexcept>
#include "crypt.hpp"



void crypto_init() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Fatal Error: Cryptographic sequence failed to initialized.");
    }

    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("Fatal Error: CPU does not support AES hardware instructions.");
    }
}


SafeVar& SafeVar::encrypt(Key key) {
    unsigned long long dummy;
    randombytes_buf(this->ptr, NONCE_LEN); // generate the nounce

    crypto_aead_aes256gcm_encrypt(
        this->ptr + NONCE_LEN, // write inplace the encrypted data to data
        &dummy, // pass dummy to the the len
        this->ptr + NONCE_LEN, this->size - ENCRYPTION_BUFF_LEN, // unencrypted data and its length
        NULL, 0, NULL, 
        this->ptr, key // nounce and key
    );

    return *this;
}

SafeVar& SafeVar::decrypt(Key key, bool no_corrupt) {
    unsigned long long dummy;
    SafeVar backup = *this;

    int error = crypto_aead_aes256gcm_decrypt(
        ptr + NONCE_LEN, // write inplace the decrypted data to data
        &dummy, // pass dummy to the the len
        NULL,
        ptr + NONCE_LEN, size - NONCE_LEN, // encrypted data data and its length
        NULL, 0,
        ptr, key // nounce and key
    );

    if (error) {
        if (no_corrupt) {
            *this = std::move(backup);
            throw std::runtime_error("Decryption failed: Incorrect password.");
        }
        throw std::runtime_error("Decryption failed: corrupted cipher.");
    }

    return *this;
}


SafeVar& SafeVar::hash(Salt salt) {
    SafeVar dest(KEY_LEN); 

    int error = crypto_pwhash(
        dest.ptr + NONCE_LEN,
        KEY_LEN,
        (char *)this->ptr + NONCE_LEN,
        this->size - ENCRYPTION_BUFF_LEN,
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (!error) *this = std::move(dest);
    else throw std::runtime_error("Failed to Hash");

    return *this;
}