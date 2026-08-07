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
    password.get_ptr(false)[0] = '0';
    password.get_ptr(false)[1] = '0';
    password.get_ptr(false)[2] = '0';
    password.get_ptr(false)[3] = '0';
    password.get_ptr(false)[4] = '\0';
    Vault vault(&password);

    vault.open_vault();

    return 0;
}