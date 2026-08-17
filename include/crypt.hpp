#pragma once

#include <cstring>
#include <utility>
#include <new>
#include "sodium.h"

namespace crypto {
    constexpr int key_len = crypto_aead_aes256gcm_KEYBYTES;
    constexpr int salt_len = crypto_pwhash_SALTBYTES;


    using Salt = unsigned char[salt_len];
    using Key = unsigned char[key_len];

    void crypt_init();

    unsigned char *random(unsigned char *target, size_t len);

    class SafeVar {
        private:
            size_t size = -1; // total allocated size in bytes
            unsigned char *ptr = nullptr;
        
        public:
            static constexpr int nonce_len = crypto_aead_aes256gcm_NPUBBYTES;
            static constexpr int auth_tag_len = crypto_aead_aes256gcm_ABYTES;
            static constexpr int encryptoion_buff_len = nonce_len + auth_tag_len;



            SafeVar() = default;

            SafeVar(size_t size) {
                this->size = size + encryptoion_buff_len;
                this->ptr = (unsigned char *)sodium_malloc(this->size);
                if (this->ptr == nullptr) throw std::bad_alloc();
            };

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

            
            unsigned char *get() { return ptr; }

            void memzero() { sodium_memzero(ptr, size); }

            SafeVar &random() { 
                randombytes(ptr, size - encryptoion_buff_len); 
                return *this;
            }
            
            SafeVar &encrypto(Key key);

            SafeVar &decrypto(Key key, bool no_corrupt);

            SafeVar &hash(Salt salt);
    };
}