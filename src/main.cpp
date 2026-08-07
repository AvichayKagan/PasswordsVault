#include "vault.hpp"
#include "crypt.hpp"

int main() {
    try {
        crypto_init();
    }
    catch (...) {
        return 1;
    }


    SafeVar password(MAX_PASSWORD_LENGTH);
    password.get()[0] = '0';
    password.get()[1] = '0';
    password.get()[2] = '0';
    password.get()[3] = '0';
    password.get()[4] = '\0';
    Vault vault(&password);

    vault.open_vault();

    return 0;
}