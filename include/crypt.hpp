#pragma once

#include <cstring>
#include <utility>
#include <new>
#include "sodium.h"

#define KEY_LEN (crypto_aead_aes256gcm_KEYBYTES)
#define SALT_LEN (crypto_pwhash_SALTBYTES)
#define NONCE_LEN (crypto_aead_aes256gcm_NPUBBYTES)
#define AUTH_TAG_LEN (crypto_aead_aes256gcm_ABYTES)
#define ENCRYPTION_BUFF_LEN (NONCE_LEN + AUTH_TAG_LEN) // the size encrytped data is more than the original data (the auth tag + nonce)


typedef unsigned char Salt[SALT_LEN];

typedef unsigned char Key[KEY_LEN];


class SafeVar {
    private:
        size_t size; // total allocated size in bytes
        unsigned char *ptr = nullptr;
    
    public:
        SafeVar() = default;

        SafeVar(unsigned char *src, size_t len, bool is_encrypted) {
            (*this).copy_data(src, len, is_encrypted);
        }

        ~SafeVar() { if (ptr != nullptr) sodium_free(ptr); }
        

        SafeVar(const SafeVar& other) {
            this->size = other.size;
            this->ptr = (unsigned char *)sodium_malloc(other.size);
            if (this->ptr == nullptr) throw std::bad_alloc();
            std::memcpy(this->ptr, other.ptr, this->size);
        }

        SafeVar& operator=(const SafeVar& other) {
            if (this == &other) return *this;

            unsigned char *temp = (unsigned char *)sodium_malloc(other.size);
            if (temp == nullptr) throw std::bad_alloc();

            this->size = other.size;
            sodium_free(this->ptr);
            this->ptr = temp;
            std::memcpy(this->ptr, other.ptr, this->size);

            return *this;
        }

        SafeVar(SafeVar&& other) noexcept {
            this->size = other.size;
            this->ptr = other.ptr;
            other.size = 0;
            other.ptr = nullptr;
        }

        SafeVar& operator=(SafeVar&& other) noexcept {
            if (this == &other) return *this;

            sodium_free(this->ptr);

            this->size = other.size;
            this->ptr = other.ptr;
            other.size = 0;
            other.ptr = nullptr;

            return *this;
        }

        void copy_data(unsigned char *src, size_t len, bool is_encrypted) {
            this->size = len + (!is_encrypted)*ENCRYPTION_BUFF_LEN;
            this->ptr = (unsigned char *)sodium_malloc(size);
            if (this->ptr == nullptr) throw std::bad_alloc();
            std::memcpy(this->ptr + (!is_encrypted)*NONCE_LEN, src, len);
        }

        void memzero() { sodium_memzero(this->ptr, this->size); }

        void random(size_t size) { 
            this->size = size + ENCRYPTION_BUFF_LEN;
            this->ptr = (unsigned char *)sodium_malloc(size);
            if (this->ptr == nullptr) throw std::bad_alloc();
            randombytes(this->ptr + NONCE_LEN, size);
        }

        unsigned char *get_data() { return this->ptr; }
        
        SafeVar &encrypt(Key key);

        SafeVar &decrypt(Key key, bool no_corrupt);

        void hash(Salt salt);
};

void crypto_init();