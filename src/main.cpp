#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"
#include "shell.hpp"

int main() {
    try {
        crypto::crypt_init();
        vault::Vault vault;
        shell::Shell shell(vault);
        std::cout << "Auto-Opening the Vault..." << std::endl;
        shell.open_public();
        shell.run();
    }
    catch (const std::exception& e) {
        std::cout << "Fatal Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}