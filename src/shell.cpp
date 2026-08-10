#include "shell.hpp"
#include "safe_io.h"


int Shell::get_code() {
    int code;

    for (code = 0; commands[code] == nullptr; code++) {
        // if (!std::strcmp(commands[code], command)) return code;
    }

    return code; // code for none
}


void Shell::add() {
    crypto::SafeVar password(config::max_password_len);

    if (vault.exists(arg)) {
        std::cout << "'" << arg.get() << "' already exists in the vault. you can change its password using 'change' or delete it using 'del'." << std::endl;
        return;
    }

    std::cout << "Please enter the password for " << arg.get() << ": " << std::flush;
    if (safeIO::input(password.get(), config::max_password_len, true)) throw std::runtime_error("Failed to take password from the user.");
    
    vault.add_password(std::move(arg), std::move(password));
    
    std::cout << arg.get() << " has been added to the vault." << std::endl;
}

void Shell::show() {
    crypto::SafeVar password = vault.search(arg);

    if (password.get() == nullptr) {
        std::cout << "No such name '"<< arg.get() << "' exists in the vault. you can add it using 'add'." << std::endl;
        return;
    }

    std::cout << "The password for '" << arg.get() << "' is: " << password.get() << ",Please press enter to delete this massage." << std::endl;
}


void Shell::run() {
    while (true) {
        // take command

        // take arg

        // validate no extra tokens?

        int code = this->get_code();

        if (code != 0 && !vault.is_open()) { // 0  is close for open
            if (code == 1) { // 1 is code for close
                std::cout << "Cannot complete the operation, the vault is closed, please type 'open' to open it." << std::endl;
            }
            else std::cout << "The vault is already closed, please type 'open' to open it." << std::endl;

            continue;
        }

        try {
            (this->*operations[code])(); // execute the command
        } 
        catch (const std::exception& e) {
            std::cerr << "Fatal Error: Could not complete opertation: " << e.what() << std::endl;
        }
    }
}