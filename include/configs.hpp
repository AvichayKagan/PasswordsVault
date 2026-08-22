#pragma once


#include <stdexcept> 
#include <string> 

namespace config {
    constexpr int max_name_len = 64;
    constexpr int max_password_len = 64 ;
    constexpr const char *vault_path = "./vault.bin";
    constexpr const char *vault_path_temp = "./vault.temp";


    class GeneralError : public std::runtime_error {
    public:
        explicit GeneralError(const std::string& message, const std::string& module, int errorCode = 1) 
            : std::runtime_error(message), _module(module), errorCode(errorCode) {}

        int code() const noexcept {
            return errorCode;
        }

        const std::string& module() const noexcept {
            return _module;
        }

    private:
        const std::string _module;
        int errorCode;
    };

    
    class FatalError : public GeneralError {
    public:
        explicit FatalError(const std::string& message, const std::string& module, int errorCode = -1) 
            : GeneralError(message, module, errorCode) {}
    };

}