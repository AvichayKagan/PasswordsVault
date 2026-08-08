#include <iostream>
#include <stdexcept>
#include "crypt.hpp"

using namespace crypto;

void crypto::crypt_init() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Fatal Error: cryptoographic sequence failed to initialized.");
    }

    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("Fatal Error: CPU does not support AES hardware instructions.");
    }
}

unsigned char* crypto::random(unsigned char *target, size_t len) { 
    randombytes(target, len); 
    return target;
}

SafeVar& SafeVar::encrypto(Key key) {
    unsigned long long dummy;
    randombytes_buf(ptr + size - nonce_len, nonce_len); // generate the nounce

    crypto_aead_aes256gcm_encrypt(
        ptr, // write inplace the encryptoed data to data
        &dummy, // pass dummy to the the len
        ptr, size - encryptoion_buff_len, // unencryptoed data and its length
        NULL, 0, NULL, 
        ptr + size - nonce_len, key // nounce and key
    );

    return *this;
}

SafeVar& SafeVar::decrypto(Key key, bool no_corrupt) {
    unsigned long long dummy;
    SafeVar backup = *this;

    int error = crypto_aead_aes256gcm_decrypt(
        ptr, // write inplace the decryptoed data to data
        &dummy, // pass dummy to the the len
        NULL,
        ptr, size - nonce_len, // encryptoed data data and its length
        NULL, 0,
        ptr + size - nonce_len, key // nounce and key
    );

    if (error) {
        if (no_corrupt) {
            *this = std::move(backup);
            throw std::runtime_error("Decryptoion failed: Incorrect password.");
        }
        throw std::runtime_error("Decryptoion failed: corrupted cipher.");
    }

    return *this;
}


SafeVar& SafeVar::hash(Salt salt) {
    SafeVar dest(key_len); 

    int error = crypto_pwhash(
        dest.ptr, // the dest to write the hash
        key_len, // the length of the hash
        (char *)this->ptr, // the data to be hashed
        this->size - encryptoion_buff_len, // the size of the data to be hashed
        salt, // the salt
        // hashing algorithm definitions
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (!error) *this = std::move(dest);
    else throw std::runtime_error("Failed to Hash");

    return *this;
}