#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"

int main() {
    try {
        crypto::crypt_init();
    }
    catch (...) {
        std::cout << "Fatal Error: cryptoographuc library faild to init." << std::endl;
        return 1;
    }


    crypto::SafeVar password(config::max_password_len);
    password.get()[0] = '0';
    password.get()[1] = '0';
    password.get()[2] = '0';
    password.get()[3] = '0';
    password.get()[4] = '\0';
    Vault vault;

    vault.open_vault();

    return 0;
}