#include "shell.hpp"

using namespace shell;

int Shell::get_code() {
    int code;

    for (code = 0; commands[code] != nullptr; code++) {
        if (!std::strcmp(commands[code], (char *)command.get())) return code;
    }

    return -1; // code for none
}

void Shell::help() {
    std::cout << "Available commands:\n"
              << "-------------------\n"
              << "  open          - Open and unlock the vault\n"
              << "  close         - Close and lock the vault\n"
              << "  add    [name] - Add a new password (flags: --gen)\n"
              << "  del    [name] - Delete an existing entry\n"
              << "  chpass [name] - Change the password of an existing entry\n"
              << "  rename [name] - Rename an entry\n"
              << "  chmaster      - Change the vault's master password\n"
              << "  list          - List all entry names in the vault\n"
              << "  show   [name] - Show a password (flags: --copy)\n"
              << "  search        - Search for entries by name\n" // update
              << "  stats         - Show vault statistics and size\n"
              << "  help          - Show this help menu\n"
              << "  exit          - Safely exit the program\n"
              << std::endl;
}

void Shell::open() { 
    crypto::SafeVar master_password(config::max_password_len);
    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
    if (vault.open_vault(master_password)) {
        std::cout << "Vault opened succesfully." << std::endl;
    }
    else std::cout << "Incorrect Master Password. Please type 'open' in the shell to try again." << std::endl;
}

void Shell::list() { 
    if (vault.is_empty()) {
        std::cout << "Vault is empty." << std::endl;
        return;
    }

    safeio::SafeStream cout("The vault content has been listed.");
    for (Dict::Node *i = vault.get_head(); i != nullptr; i = i->get_next() ) {
        cout << safeio::Secret(i->name.get()) << safeio::endl;
    }
    cout << "\nPress any key to delete the list..." << safeio::flush;
    safeio::key_press();
}

void Shell::stats() {
    int size = vault.get_size();
    int count = vault.get_count();

    std::cout << "Total passwords in the vault: " << count << std::endl;
    std::cout << "Vault file size is: " << size << " Bytes." << std::endl;
}

void Shell::close() { 
    vault.close_vault();
    std::cout << "Vault closed succesfully. Use 'open' to reopen it." << std::endl;
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
    if (safeio::input(password.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
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
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
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

    safeio::SafeStream cout("A password has been showed.");
    cout << "The password for '" << safeio::Secret(arg.get()) << "' is: '" << safeio::Secret(password.get()) << "', Press any key to delete this massage, or 'c' to copy the password." << safeio::flush;
    int ch = safeio::key_press();
    if (ch == 'c') {

        // copy
        cout.set_msg("Password has been copied!");
    }
}


void Shell::chpass() {
    crypto::SafeVar password(config::max_password_len);

    if (!vault.exists(arg)) {
        std::cout << "No entry '"<< arg.get() << "' exists in the vault." << std::endl;
        return;
    }

    std::cout << "Please enter the new password for " << arg.get() << ": " << std::flush;
    if (safeio::input(password.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
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
    if (safeio::input(new_name.get(), config::max_name_len, false)) throw Error("Failed to take password from the user.");
    

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault.change_name(arg, std::move(new_name), std::move(master_password))) {
            std::cout << "Name has been change successfully." << std::endl;
            break;
        }
        std::cout << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}


void Shell::chmaster() {
    crypto::SafeVar new_master(config::max_password_len);

    std::cout << "Please enter a new master password for the vault: " << std::flush;
    if (safeio::input(new_master.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    
    std::cout << "Please enter the old master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault.change_master(new_master, std::move(master_password))) {
            std::cout << "Master password has been change successfully." << std::endl;
            break;
        }
        std::cout << "Incorrect Old Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::run() {
    crypto::SafeVar input(max_input_len);
    int code;

    open();

    std::cout << "Shell is running, please enter commands to use the vault.." << std::endl;

    while (is_running) {
        std::cout << std::endl;
        if (safeio::input(input.get(), max_input_len, false)) throw Error("Failed to read command from the user.");

        if (!this->parse(input.get(), &code)) continue;

        if (code != 0 && code != 2 && code != 3 && !vault.is_open()) { // 0  is code for open, 2 is code for exit, 3 is for help
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

        reset();
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