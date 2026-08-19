#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"
#include "shell.hpp"

int main() {
    try {
        crypto::crypt_init();
        vault::Vault vault;
        std::cout << "Auto-Opening the Vault..." << std::endl;
        vault.open_vault();
        shell::Shell shell(vault);
        shell.run();
    }
    catch (const std::exception& e) {
        std::cout << "Fatal Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}