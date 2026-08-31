#include <iostream>
#include <stdexcept>
#include "crypt.hpp"

using namespace crypto;

void crypto::crypt_init() {
    if (sodium_init() < 0) {
        throw Error("Cryptographic sequence failed to initialized.", ErrorCode::InitFail);
    }

    if (!crypto_aead_aes256gcm_is_available()) {
        throw Error("CPU does not support AES hardware instructions.", ErrorCode::AESSupportMissing);
    }
}

unsigned char* crypto::random(unsigned char *target, size_t len) { 
    randombytes(target, len); 
    return target;
}

void SafeVar::encrypto(Key key) {
    unsigned long long dummy;
    randombytes_buf(ptr.get() + size - nonce_len, nonce_len); // generate the nounce

    crypto_aead_aes256gcm_encrypt(
        ptr.get(), // write inplace the encryptoed data to data
        &dummy, // pass dummy to the the len
        ptr.get(), size - encryptoion_buff_len, // unencryptoed data and its length
        NULL, 0, NULL, 
        ptr.get() + size - nonce_len, key // nounce and key
    );
}

void SafeVar::decrypto(Key key, bool no_corrupt) {
    unsigned long long dummy;
    SafeVar backup = *this;

    int error = crypto_aead_aes256gcm_decrypt(
        ptr.get(), // write inplace the decryptoed data to data
        &dummy, // pass dummy to the the len
        NULL,
        ptr.get(), size - nonce_len, // encryptoed data data and its length
        NULL, 0,
        ptr.get() + size - nonce_len, key // nounce and key
    );

    if (error) {
        if (no_corrupt) {
            *this = std::move(backup);
            throw Error("Decryption failed: Incorrect password.", ErrorCode::IncorrectPassword);
        }
        throw Error("Decryptoion failed: corrupted cipher.", ErrorCode::CurrptedCipher);
    }
}


SafeVar& SafeVar::hash(Salt salt) {
    SafeVar dest(key_len); 

    int error = crypto_pwhash(
        dest.ptr.get(), // the dest to write the hash
        key_len, // the length of the hash
        (char *)ptr.get(), // the data to be hashed
        size - encryptoion_buff_len, // the size of the data to be hashed
        salt, // the salt
        // hashing algorithm definitions
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (!error) *this = std::move(dest);
    else throw Error("Failed to Hash", ErrorCode::HashFail);

    return *this;
}

void SafeVar::short_hash_pepper_gen(const char context[crypto_kdf_CONTEXTBYTES]) {
    SafeVar dest(short_hash_pepper_len); 

    crypto_kdf_derive_from_key(
        dest.get(),
        short_hash_pepper_len,
        0,
        context,
        ptr.get()
    );

    *this = std::move(dest);
}

size_t SafeVar::short_hash(const SafeVar &pepper, size_t inlen) const {
    unsigned char out[short_hash_len]; 
    size_t ret;

    crypto_shorthash(
        out,
        ptr.get(), inlen,
        pepper.get()
    );

    std::memcpy(&ret, out, sizeof(size_t));

    return ret;
}