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
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeIO::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault.add_password(std::move(name), std::move(password), std::move(master_password))) {
            std::cout << "Password has been added to the vault." << std::endl;
            break;
        }
        std::cout << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::del() {
    if (!vault.exists(arg)) {
        std::cout << "Cannot delete '"<< arg.get() << "' as it doesn't exists in the vault." << std::endl;
        return;
    }

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;

    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeIO::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;
        
        if (vault.del_password(arg, std::move(master_password))) {
            std::cout << arg.get() << " has been deleted from the vault." << std::endl;
            break;
        }
        std::cout << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::show() {
    crypto::SafeVar password = vault.search(arg);

    if (password.get() == nullptr) {
        std::cout << "No such name '"<< arg.get() << "' exists in the vault. you can add it using 'add'." << std::endl;
        return;
    }

    // must securley print this!
    std::cout << "The password for '" << arg.get() << "' is: '" << password.get() << "', Press any key to delete this massage, or 'v' to copy the password." << std::endl;
}


void Shell::chpass() {
    crypto::SafeVar password(config::max_password_len);

    if (!vault.exists(arg)) {
        std::cout << "No entry '"<< arg.get() << "' exists in the vault." << std::endl;
        return;
    }

    std::cout << "Please enter the new password for " << arg.get() << ": " << std::flush;
    if (safeIO::input(password.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeIO::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault.change_password(arg, std::move(password), std::move(master_password))) {
            std::cout << "Password has been change successfully." << std::endl;
            break;
        }
        std::cout << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::rename() {
    crypto::SafeVar new_name(config::max_name_len);

    if (!vault.exists(arg)) {
        std::cout << "No entry '"<< arg.get() << "' exists in the vault." << std::endl;
        return;
    }

    std::cout << "Please enter the new name for " << arg.get() << ": " << std::flush;
    if (safeIO::input(new_name.get(), config::max_name_len, false)) throw Error("Failed to take password from the user.");
    

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeIO::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault.change_name(arg, std::move(new_name), std::move(master_password))) {
            std::cout << "Name has been change successfully." << std::endl;
            break;
        }
        std::cout << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::run() {
    crypto::SafeVar input(max_input_len);
    int code;

    std::cout << "Shell is running, please enter commands to use the vault.." << std::endl;

    while (is_running) {
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
        catch (const config::FatalError& e) {
            throw;
        }
        catch (const config::GeneralError& e) {
            std::cerr << "Error: Could not complete opertation: " << e.what() << " (MODULE: " << e.module() << ", CODE: "<< e.code() << ")" << '\n';
        }
        catch (const std::exception& e) {
            std::cerr << "Error: Could not complete opertation: " << e.what() << '\n';
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