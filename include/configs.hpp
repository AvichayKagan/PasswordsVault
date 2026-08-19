#pragma once


#include <stdexcept> 
#include <string> 

namespace config {
    constexpr int max_name_len = 64;
    constexpr int max_password_len = 64 ;
    constexpr const char *vault_path = "./vault.bin";


    class GeneralError : public std::runtime_error {
    public:
        explicit GeneralError(const std::string& message, int errorCode = 1) 
            : std::runtime_error(message), errorCode(errorCode) {}

        int code() const noexcept {
            return errorCode;
        }

    private:
        int errorCode;
    };


}