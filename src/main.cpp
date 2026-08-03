#include "vault.hpp"
#include "crypt.hpp"

int main() {
    Vault vault(false);

    try {
        crypto_init();
    }
    catch (...) {
        return 1;
    }

    vault.open_vault();

    return 0;
}