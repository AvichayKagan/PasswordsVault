#include "shell.hpp"

namespace shell {

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
    if (vault->is_open()) {
        std::cout << "The vault is already open, type 'help' to see available commands." << std::endl;
        return;
    }

    crypto::SafeVar master_password(config::max_password_len);
    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
    if (vault->open_vault(std::move(master_password))) {
        std::cout << "Vault opened succesfully." << std::endl;
    }
    else std::cout << "Incorrect Master Password. Please type 'open' in the shell to try again." << std::endl;
}

void Shell::list() {
    if (vault->is_empty()) {
        std::cout << "Vault is empty." << std::endl;
        return;
    }

    safeio::SafeStream cout("The vault content has been listed.");
    for (const auto& i : *vault) {
        cout << safeio::Secret(i.first.get()) << safeio::endl;
    }
    cout << "\nPress any key to delete the list..." << safeio::flush;
    safeio::key_press();
}

void Shell::info() {
    bool is_open = vault->is_open();
    int size = is_open ? vault->get_size() : -1;
    int count = is_open ? vault->get_count() : -1;
    const char *state = is_open ? "OPEN" : "CLOSED";
    
    std::cout << " ==== Vault Status ====" << "\n\n";
    std::cout << " Path:   ./vault.bin" << '\n';
    std::cout << " State: " << state << '\n';

    if (is_open) {
        int noise = 100 - (100*count) / ((size - disk::DiskManager::pre_plus_header_size - crypto::SafeVar::encryptoion_buff_len)/(config::max_name_len + config::max_password_len));

        std::cout << '\n';
        std::cout << " -- Storage Metrics --" << '\n';
        std::cout << " Passwords Count: " << count << '\n';
        std::cout << " File Size: " << size << " Bytes\n";
        std::cout << " Noise Overhead: ~" << noise << "%\n";
    }

    std::cout << "\n ======================" << std::endl;
}                  

void Shell::close() { 
    if (vault->is_open()) {
        vault->close_vault();
        std::cout << "Vault closed succesfully. Use 'open' to reopen it." << std::endl;
    }
    else std::cout << "The vault is already closed, please type 'open' to open it." << std::endl;
}


void Shell::add() {
    crypto::SafeVar password(config::max_password_len);

    if (vault->contains(encoding.arg)) {
        std::cout << "'" << encoding.arg.get() << "' already exists in the vault. you can change its password using 'change' or delete it using 'del'." << std::endl;
        return;
    }

    std::cout << "Please enter the password for " << encoding.arg.get() << ": " << std::flush;
    if (safeio::input(password.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault->add_password(std::move(encoding.arg), std::move(password), std::move(master_password))) {
            std::cout << "Password has been added to the vault." << std::endl;
            break;
        }
        std::cout << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::del() {
    if (!vault->contains(encoding.arg)) {
        std::cout << "Cannot delete '"<< encoding.arg.get() << "' as it doesn't exists in the vault." << std::endl;
        return;
    }

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;

    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;
        
        if (vault->del_password(encoding.arg, std::move(master_password))) {
            std::cout << encoding.arg.get() << " has been deleted from the vault." << std::endl;
            break;
        }
        std::cout << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::show() {
    crypto::SafeVar password = vault->search(encoding.arg);

    if (password.get() == nullptr) {
        std::cout << "No such name '"<< encoding.arg.get() << "' exists in the vault. you can add it using 'add'." << std::endl;
        return;
    }

    safeio::SafeStream cout("A password has been showed.");
    cout << "The password for '" << safeio::Secret(encoding.arg.get()) << "' is: '" << safeio::Secret(password.get()) << "', Press any key to delete this massage, or 'c' to copy the password." << safeio::flush;
    int ch = safeio::key_press();
    if (ch == 'c') {

        // copy
        cout.set_msg("Password has been copied!");
    }
}


void Shell::chpass() {
    crypto::SafeVar password(config::max_password_len);

    if (!vault->contains(encoding.arg)) {
        std::cout << "No entry '"<< encoding.arg.get() << "' exists in the vault." << std::endl;
        return;
    }

    std::cout << "Please enter the new password for " << encoding.arg.get() << ": " << std::flush;
    if (safeio::input(password.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault->change_password(encoding.arg, std::move(password), std::move(master_password))) {
            std::cout << "Password has been change successfully." << std::endl;
            break;
        }
        std::cout << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}


void Shell::rename() {
    crypto::SafeVar new_name(config::max_name_len);

    if (!vault->contains(encoding.arg)) {
        std::cout << "No entry '"<< encoding.arg.get() << "' exists in the vault." << std::endl;
        return;
    }

    std::cout << "Please enter the new name for " << encoding.arg.get() << ": " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(new_name.get(), config::max_name_len, false)) throw Error("Failed to take password from the user.");
        if (*new_name.get() == '\0') return;

        if (!vault->contains(new_name)) break;
        std::cout << "The new name already exists in the vault! Please choose a different name or press enter to exit: " << std::flush;
    }

    std::cout << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault->change_name(std::move(encoding.arg), new_name, std::move(master_password))) {
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

        if (vault->change_master(std::move(new_master), std::move(master_password))) {
            std::cout << "Master password has been change successfully." << std::endl;
            break;
        }
        std::cout << "Incorrect Old Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::run() {
    int max_input_len = 100; // temp
    crypto::SafeVar input(max_input_len);

    if (vault == nullptr) {
        crypto::SafeVar master_password(config::max_password_len);
        std::cout << "Please choose and enter a master password for the new vault: " << std::flush;
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the vault password from the user.");
        vault = std::make_unique<vault::Vault>(std::move(master_password));
    }
    
    if (!vault->is_open()) {
        std::cout << "Auto-Opening the vault..." << std::endl;
        open(); // could be pre opend in the case of init vault
    }

    std::cout << "Shell is running, please enter commands to use the vault..." << std::endl;

    while (vault != nullptr) {
        std::cout << std::endl;
        if (safeio::input(input.get(), max_input_len, false)) throw Error("Failed to read command from the user.");

        encoding = parse(input);

        if (!vault->is_open() && !commands[encoding.command].allow_close) {
            std::cout << "Cannot complete the operation, the vault is closed, please type 'open' to open it." << std::endl;
            continue;
        }

        try {
            std::cout << std::endl;
            (this->*commands[encoding.command].method)(); // execute the command
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
    }
}


} // namespace shell