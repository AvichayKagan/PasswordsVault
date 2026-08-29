#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"
#include "shell.hpp"
#include "safe_io.hpp"

int main() {
    try {
        if (!safeio::is_interactive_terminal()) throw std::runtime_error("The vault can only be run in an interactive terminal.");
        safeio::SafeTerminal safe_terminal_token;
        crypto::crypt_init();

        vault::Vault vault;

        shell::Shell shell(vault);

        shell.run();
    }
    catch (const config::GeneralError& e) {
        std::cerr << "Fatal Error: " << e.what() << " (MODULE: " << e.module() << ", CODE: "<< e.code() << ")" << '\n';
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal Error: " << e.what() << '\n';
        return 1;
    }
    catch (...) {
        std::cerr << "Unexpected Fatal Error" << '\n';
        return 1;
    }

    return 0;
}