#include "shell.hpp"
#include "safe_io.h"

using namespace shell;

int Shell::get_code() {
    int code;

    for (code = 0; commands[code] != nullptr; code++) {
        if (!std::strcmp(commands[code], (char *)command.get())) return code;
    }

    return -1; // code for none
}


void Shell::add() {
    crypto::SafeVar password(config::max_password_len);
    crypto::SafeVar name = arg;
    name.realloc(config::max_name_len);

    if (vault.exists(name)) {
        std::cout << "'" << name.get() << "' already exists in the vault. you can change its password using 'change' or delete it using 'del'." << std::endl;
        return;
    }

    std::cout << "Please enter the password for " << name.get() << ": " << std::flush;
    if (safeIO::input(password.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (!vault.add_password(std::move(name), std::move(password))) {
        std::cout << "Incorrect Master Password. Please try again: " << std::flush;
        // exit the loop somehow
    }

    std::cout << "password has been added to the vault." << std::endl;
}

void Shell::del() {
    if (!vault.exists(arg)) {
        std::cout << "Cannot delete '"<< arg.get() << "' as it doesn't exists in the vault." << std::endl;
        return;
    }

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (!vault.del_password(arg)) {
        std::cout << "Incorrect Master Password. Please try again: " << std::flush;
        // exit the loop somehow
    }
    
    std::cout << arg.get() << " has been deleted from the vault." << std::endl;
}

void Shell::show() {
    crypto::SafeVar password = vault.search(arg);

    if (password.get() == nullptr) {
        std::cout << "No such name '"<< arg.get() << "' exists in the vault. you can add it using 'add'." << std::endl;
        return;
    }

    std::cout << "The password for '" << arg.get() << "' is: " << password.get() << "   ,Please press enter to delete this massage." << std::endl;
}


void Shell::run() {
    crypto::SafeVar input(max_input_len);
    int code;

    std::cout << "Shell is running, please enter commands to use the vault.." << std::endl;

    while (true) {
        std::cout << std::endl;
        if (safeIO::input(input.get(), max_input_len, false)) throw Error("Failed to read command from the user.");

        if (!this->parse(input.get(), &code)) continue;

        if (code != 0 && !vault.is_open()) { // 0  is code for open
            if (code == 1) { // 1 is code for close
                std::cout << "The vault is already closed, please type 'open' to open it." << std::endl;
            }
            else std::cout << "Cannot complete the operation, the vault is closed, please type 'open' to open it." << std::endl;

            continue;
        }

        try {
            std::cout << std::endl;
            (this->*operations[code])(); // execute the command
        } 
        catch (const config::GeneralError& e) {
            std::cerr << "Error: Could not complete opertation: " << e.what() << "(code "<< e.code() << ")" << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "Error: Could not complete opertation: " << e.what() << std::endl;
        }

        this->reset();
    }
}

bool Shell::parse(unsigned char *input, int *code) {
    char *cmd = (char *)command.get();
    char *arg = (char *)this->arg.get();

    while (std::isspace(*input)) input++;
    if (*input == '\0') return false;

    while (*input != '\0' && !std::isspace(*input)) {
        *cmd = *input;
        cmd++;
        input++;
    }
    *cmd = '\0';
    *code = this->get_code();

    if (*code == -1) {
        std::cout << "Unrecognized command '"<< command.get() << "', did you mean '' ? please type 'help' to list the avalible commands." << std::endl;
        return false;
    }

    while (std::isspace(*input)) input++;
     if (*input == '\0' && commands_has_arg[*code]) {
        std::cout << "Missing argument." << std::endl;
        return false;
    }

    while (*input != '\0' && !std::isspace(*input)) {
        *arg = *input;
        arg++;
        input++;
    }
    *arg = '\0';

    while (std::isspace(*input)) input++;
    if (*input != '\0') {
        std::cout << "Too many arguments." << std::endl;
        return false;
    }

    return true;
}