#pragma once

#include <cstring>
#include <utility>
#include <memory>
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
            struct Deleter {
                void operator()(unsigned char* ptr) const { sodium_free(ptr); }
            };

            using SafePtr = std::unique_ptr<unsigned char[], Deleter>;
            
            size_t size = 0; // total allocated size in bytes
            SafePtr ptr;
            // contract: ptr == nullptr <=> size == 0

        
        public:
            static constexpr int nonce_len = crypto_aead_aes256gcm_NPUBBYTES;
            static constexpr int auth_tag_len = crypto_aead_aes256gcm_ABYTES;
            static constexpr int short_hash_len = crypto_shorthash_BYTES;
            static constexpr int short_hash_pepper_len = crypto_shorthash_KEYBYTES;
            static constexpr int encryptoion_buff_len = nonce_len + auth_tag_len;

            // add swap method

            SafeVar() = default;

            explicit SafeVar(size_t _size, bool random = false) : size(_size + encryptoion_buff_len), ptr((unsigned char *)sodium_malloc(size)) {
                if (ptr == nullptr) throw std::bad_alloc();
                if (random) randombytes(ptr.get(), _size);
            };

            ~SafeVar() = default;
            
            SafeVar(const SafeVar& other) :size(other.size) {
                if (size == 0) return;
                
                ptr.reset((unsigned char *)sodium_malloc(size));
                if (ptr == nullptr) throw std::bad_alloc();
                std::memcpy(ptr.get(), other.ptr.get(), size);
            }

            SafeVar& operator=(const SafeVar& other) {
                if (this == &other) return *this;

                // same size optimization (no realloc)
                if (size == other.size) {
                    if (ptr != nullptr) std::memcpy(ptr.get(), other.ptr.get(), size);
                    return *this;
                }


                // set a new memory pointer for 'this'
                SafePtr temp;
                if (other.size != 0) {
                    temp.reset((unsigned char *)sodium_malloc(other.size));
                    if (temp == nullptr) throw std::bad_alloc();
                    std::memcpy(temp.get(), other.ptr.get(),  other.size);
                }

                // set the this object
                size = other.size;
                ptr = std::move(temp);

                return *this;
            }

            SafeVar(SafeVar&& other) noexcept : size(other.size), ptr(std::move(other.ptr)) { other.size = 0; }

            SafeVar& operator=(SafeVar&& other) noexcept {
                if (this == &other) return *this;

                size = other.size;
                other.size = 0;
                ptr = std::move(other.ptr);

                return *this;
            }

            
            unsigned char *get() const { return ptr.get(); }

            size_t get_size() const { return size; }

            void memzero() { sodium_memzero(ptr.get(), size); }

            // never use on encrypted data
            void realloc(size_t new_size) { 
                SafeVar temp(new_size);

                if (ptr != nullptr) {
                    size_t copy_len = (new_size + encryptoion_buff_len < size) ? new_size : size - encryptoion_buff_len;
                    std::memcpy(temp.ptr.get(), ptr.get(), copy_len);
                }

                *this = std::move(temp);
            }

            SafeVar &random() { 
                randombytes(ptr.get(), size - encryptoion_buff_len); 
                return *this;
            }
            
            void encrypto(Key key);

            void decrypto(Key key, bool no_corrupt);

            SafeVar &hash(Salt salt);

            void short_hash_pepper_gen(const char context[crypto_kdf_CONTEXTBYTES]);

            size_t short_hash(const SafeVar &pepper, size_t inlen) const;
    };
}