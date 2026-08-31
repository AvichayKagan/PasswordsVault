#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"
#include "shell.hpp"
#include "safe_io.hpp"

int main() {
    try {
        crypto::crypt_init();
        shell::Shell shell;
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