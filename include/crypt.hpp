#pragma once

#include <cstring>
#include <utility>
#include <new>
#include "sodium.h"
#include "configs.hpp"

namespace crypto {
    constexpr int key_len = crypto_aead_aes256gcm_KEYBYTES;
    constexpr int salt_len = crypto_pwhash_SALTBYTES;


    class Error : public config::GeneralError {
    public:
        explicit Error(const std::string& message, int errorCode = 1) 
            : config::GeneralError(message, "CRYPTO", errorCode) {}
    };

    enum ErrorCode {
        InitFail    = 1,
        AESSupportMissing   = 2,

        IncorrectPassword    = 11,
        CurrptedCipher    = 12,

        HashFail          = 21,
    };

    using Salt = unsigned char[salt_len];
    using Key = unsigned char[key_len];

    void crypt_init();

    unsigned char *random(unsigned char *target, size_t len);

    class SafeVar {
        private:
            size_t size = 0; // total allocated size in bytes
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
                if (other.size == 0) return;

                this->size = other.size;
                this->ptr = (unsigned char *)sodium_malloc(other.size);
                if (this->ptr == nullptr) throw std::bad_alloc();
                std::memcpy(this->ptr, other.ptr, this->size);
            }

            SafeVar& operator=(const SafeVar& other) {
                if (this == &other) return *this;

                // same size optimization (no realloc)
                if (this->size == other.size) {
                    if (this->ptr != nullptr) std::memcpy(this->ptr, other.ptr, this->size);
                    return *this;
                }


                // set a new memory pointer for 'this'
                unsigned char *temp = nullptr;
                if (other.size != 0) {
                    temp = (unsigned char *)sodium_malloc(other.size);
                    if (temp == nullptr) throw std::bad_alloc();
                    std::memcpy(temp, other.ptr,  other.size);
                }

                // set the this object
                this->size = other.size;
                if (this->ptr != nullptr) sodium_free(this->ptr);
                this->ptr = temp;

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

                if (this->ptr != nullptr) sodium_free(this->ptr);

                this->size = other.size;
                this->ptr = other.ptr;
                other.size = 0;
                other.ptr = nullptr;

                return *this;
            }


            /*bool operator==(const SafeVar& rhs) const noexcept {
                if (ptr == rhs.ptr) return true;
                
                if (size != rhs.size) return false;

                return !sodium_memcmp(ptr, rhs.ptr, size);
            }*/

            bool operator==(const SafeVar& rhs) const noexcept {
                if (ptr == nullptr || rhs.ptr == nullptr) return false;

                return !strcmp((char*)ptr, (char*)rhs.ptr);
            }

            
            unsigned char *get() const { return ptr; }

            size_t get_size() { return size; }

            void memzero() { sodium_memzero(ptr, size); }

            // never use on encrypted data
            void realloc(size_t new_size) { 
                size_t total_new_size = new_size + encryptoion_buff_len;
                
                unsigned char *new_ptr = (unsigned char *)sodium_malloc(total_new_size);
                if (new_ptr == nullptr) throw std::bad_alloc();

                size_t copy_len = (total_new_size < size) ? new_size : size - encryptoion_buff_len;
                std::memcpy(new_ptr, ptr, copy_len);

                sodium_free(ptr);
                size = total_new_size;
                ptr = new_ptr;
            }

            SafeVar &random() { 
                randombytes(ptr, size - encryptoion_buff_len); 
                return *this;
            }
            
            void encrypto(Key key);

            void decrypto(Key key, bool no_corrupt);

            SafeVar &hash(Salt salt);
    };
}