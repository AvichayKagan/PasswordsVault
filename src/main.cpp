#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"

int main() {
    try {
        crypto_init();
    }
    catch (...) {
        std::cout << "Fatal Error: Cryptographuc library faild to init." << std::endl;
        return 1;
    }


    SafeVar password(MAX_PASSWORD_LENGTH);
    password.get()[0] = '0';
    password.get()[1] = '0';
    password.get()[2] = '0';
    password.get()[3] = '0';
    password.get()[4] = '\0';
    Vault vault;

    vault.open_vault();

    return 0;
}