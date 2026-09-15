#include "shell.hpp"

namespace shell {
    

void Shell::help() {
    std::cout << "Available commands:\n"
                << "-------------------\n";
    for (int i = 0; commands[i].name != nullptr; i++) {
        const char *arg =  commands[i].has_arg ? "[name]" : "      ";
        if (!strcmp(commands[i].name, "import")) arg = "[path]"; // ad hoc but works
        std::cout << "  " << std::left << std::setw(max_command_len + 1) << commands[i].name << arg << " - " << commands[i].desc_short << '\n';
    }
    std::cout << "\n Use '[command name] -info' for additional information on each command (e.g. flags, specs, security consideration, etc...)" << std::endl;
}


void Shell::open() { 
    if (vault->is_open()) {
        std::clog << "The vault is already open, type 'help' to see available commands." << std::endl;
        return;
    }

    crypto::SafeVar master_password(config::max_password_len);
    std::clog << "Please enter the master password to continue with this operation: " << std::flush;
    if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
    if (vault->open_vault(std::move(master_password))) {
        std::clog << "Vault opened succesfully." << std::endl;
    }
    else std::clog << "Incorrect Master Password. Please type 'open' in the shell to try again." << std::endl;
}

void Shell::list() {
    if (vault->is_empty()) {
        std::clog << "Vault is empty." << std::endl;
        return;
    }

    for (const auto& i : *vault) {
        std::cout << i.first.get() << std::endl;
    }
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
        std::cout << "\033[2J\033[3J\033[H" << std::flush;
        vault->close_vault();
        std::clog << "Vault closed succesfully. Use 'open' to reopen it." << std::endl;
    }
    else std::clog << "The vault is already closed, please type 'open' to open it." << std::endl;
}


void Shell::add() {
    crypto::SafeVar password(config::max_password_len);

    if (vault->contains(encoding.arg)) {
        std::clog << "'" << encoding.arg.get() << "' already exists in the vault. you can change its password using 'change' or delete it using 'del'." << std::endl;
        return;
    }

    if (encoding.flags & COPY) {
        std::clog << "copy flag detected!" << std::endl;
    }

    if (encoding.flags & GEN) {
        if (!encoding.flag_args.empty()) password.random_ascii(encoding.flag_args[0]);
        else password.random_ascii();
    }
    else {
        std::clog << "Please enter the password for " << encoding.arg.get() << ": " << std::flush;
        if (safeio::input(password.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    }
    

    std::clog << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault->add_password(std::move(encoding.arg), std::move(password), std::move(master_password))) {
            std::clog << "Password has been added to the vault." << std::endl;
            break;
        }
        std::clog << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::del() {
    if (!vault->contains(encoding.arg)) {
        std::clog << "Cannot delete '"<< encoding.arg.get() << "' as it doesn't exists in the vault." << std::endl;
        return;
    }

    std::clog << "Please enter the master password to continue with this operation: " << std::flush;

    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;
        
        if (vault->del_password(encoding.arg, std::move(master_password))) {
            std::clog << encoding.arg.get() << " has been deleted from the vault." << std::endl;
            break;
        }
        std::clog << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}

void Shell::show() {
    crypto::SafeVar password = vault->search(encoding.arg);

    if (password.get() == nullptr) {
        std::clog << "No such name '"<< encoding.arg.get() << "' exists in the vault. you can add it using 'add'." << std::endl;
        return;
    }

    safeio::SafeStream temp_out;
    safeio::SafeStream temp_log(std::clog, temp_out);
    temp_out << "The password for '" << encoding.arg << "' is: '" << password << "'.";
    temp_log << " Press any key to delete this massage, or 'c' to copy the password." << safeio::endl;
    int ch = safeio::key_press();
    if (ch == 'c') {
        // copy
    }
    temp_out.reset();
    std::clog << "A password has been showed." << std::endl;
}


void Shell::chpass() {
    crypto::SafeVar password(config::max_password_len);

    if (!vault->contains(encoding.arg)) {
        std::clog << "No entry '"<< encoding.arg.get() << "' exists in the vault." << std::endl;
        return;
    }

    std::clog << "Please enter the new password for " << encoding.arg.get() << ": " << std::flush;
    if (safeio::input(password.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    

    std::clog << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault->add_password(std::move(encoding.arg), std::move(password), std::move(master_password))) {
            std::clog << "Password has been change successfully." << std::endl;
            break;
        }
        std::clog << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}


void Shell::rename() {
    crypto::SafeVar new_name(config::max_name_len);

    if (!vault->contains(encoding.arg)) {
        std::clog << "No entry '"<< encoding.arg.get() << "' exists in the vault." << std::endl;
        return;
    }

    std::clog << "Please enter the new name for " << encoding.arg.get() << ": " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(new_name.get(), config::max_name_len, false)) throw Error("Failed to take password from the user.");
        if (*new_name.get() == '\0') return;

        if (!vault->contains(new_name)) break;
        std::clog << "The new name already exists in the vault! Please choose a different name or press enter to exit: " << std::flush;
    }

    std::clog << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault->change_name(std::move(encoding.arg), new_name, std::move(master_password))) {
            std::clog << "Name has been change successfully." << std::endl;
            break;
        }
        std::clog << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}


void Shell::chmaster() {
    crypto::SafeVar new_master(config::max_password_len);

    std::clog << "Please enter a new master password for the vault: " << std::flush;
    if (safeio::input(new_master.get(), config::max_password_len, true)) throw Error("Failed to take password from the user.");
    
    std::clog << "Please enter the old master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault->change_master(std::move(new_master), std::move(master_password))) {
            std::clog << "Master password has been change successfully." << std::endl;
            break;
        }
        std::clog << "Incorrect Old Master Password. Please try again or press enter to exit: " << std::flush;
    }
}


void Shell::import() { // need to implmet the del flag
    bool overwrite = encoding.flags & OVERWRITE;
    bool clear = encoding.flags & CLEAR;

    if (clear) {
        std::clog << "This operation will clear out all existing passwords in the vault (" << vault->get_count() << " passwords). are you sure you want to continue? (y/n)" << std::endl;;
        int ch = safeio::key_press(); // will not wait for enter!
        if (ch != 'y' && ch != 'Y') return;
    }

    std::clog << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') return;

        auto [inserted, changed] = vault->import_passwords(encoding.arg, std::move(master_password), overwrite, clear);
        if (inserted != -1) {
            if (clear) std::clog << "The vault has been cleared and ";
            std::clog << inserted + (overwrite ? changed : 0) << " passwords has been imported to the vault.\n";
            if (!clear) {
                std::clog << " -> " << inserted << " new passwords.\n";
                if (overwrite) {
                    std::clog << " -> " << changed << " changed passwords." << std::endl;
                }
                else std::clog << " -> " << changed << " entries already existed in the vault, remain unchanged.";
            }
            std::clog << '\n' << std::endl;
            break;
        }
        std::clog << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }

    if (!(encoding.flags & DEL)) {
        std::clog << "It is highly recommended to securly delete the import file after importing. do you want to delete it (if import succeeded)? (y/n)" << std::endl;
        int ch = safeio::key_press(); // will not wait for enter!
        if (ch != 'y' && ch != 'Y') {
            std::clog << "Warning: import file '" << encoding.arg.get() <<  "' has not been deleted." << std::endl;
            return;
        }
    }

    try {
        vault::secure_delete(encoding.arg);
        std::clog << "Import file '" << encoding.arg.get() <<  "' has been deleted." << std::endl;
    }
    catch (const config::GeneralError& e) {
        std::clog << "Warning: secure deletion of the import file '" << encoding.arg.get() <<  "' has failed, " << e.what() << " (MODULE: " << e.module() << ", CODE: "<< e.code() << ")" << '\n';
    }
    catch (const std::exception& e) {
        std::clog << "Warning: secure deletion of the import file '" << encoding.arg.get() <<  "' has failed, " << e.what() << '\n';
    }
    catch (...) {
        std::clog << "Warning: secure deletion of the import file '" << encoding.arg.get() <<  "' has failed.\n";
    }
}


void Shell::clear() {
    char ch;
    std::clog << "This operation will clear out all existing passwords in the vault (" << vault->get_count() << " passwords). are you sure you want to continue? (y/n)";
    std::cin >> ch; // flush here the stdin!
    if (ch != 'y' && ch != 'Y') return; // BUG: immidetly go without pressing enter

    std::clog << "Please enter the master password to continue with this operation: " << std::flush;
    while (true) {
        crypto::SafeVar master_password(config::max_password_len);
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
        if (*master_password.get() == '\0') break;

        if (vault->clear(std::move(master_password))) {
            std::clog << "All vault entries have been cleared." << std::endl;
            break;
        }
        std::clog << "Incorrect Master Password. Please try again or press enter to exit: " << std::flush;
    }
}


void Shell::run() {
    crypto::SafeVar instruction(max_input_len);

    if (vault == nullptr) {
        crypto::SafeVar master_password(config::max_password_len);
        std::clog << "Please choose and enter a master password for the new vault: " << std::flush;
        if (safeio::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the vault password from the user.");
        vault = std::make_unique<vault::Vault>(std::move(master_password));
    }
    
    if (!vault->is_open()) {
        std::clog << "Auto-Opening the vault..." << std::endl;
        open(); // could be pre opend in the case of init vault
    }

    std::clog << "Shell is running, please enter commands to use the vault..." << std::endl;

    while (vault != nullptr) {
        std::clog << std::endl;
        if (safeio::input(instruction.get(), max_input_len, false)) throw Error("Failed to read command from the user.");

        encoding = parse(instruction);
        if (!encoding.error.empty()) {
            std::clog << encoding.error;
            continue;
        }

        if (encoding.flags & INFO) {
            std::cout << commands[encoding.command].desc_long << std::endl;
            continue;
        }

        if (!vault->is_open() && !commands[encoding.command].allow_close) {
            std::clog << "Cannot complete the operation, the vault is closed, please type 'open' to open it." << std::endl;
            continue;
        }

        try {
            std::clog << std::endl;
            (this->*commands[encoding.command].method)(); // execute the command
        } 
        catch (const config::FatalError& e) {
            throw;
        }
        catch (const config::GeneralError& e) {
            std::clog << "Error: Could not complete opertation: " << e.what() << " (MODULE: " << e.module() << ", CODE: "<< e.code() << ")" << '\n';
        }
        catch (const std::exception& e) {
            std::clog << "Error: Could not complete opertation: " << e.what() << '\n';
        }
    }
}


} // namespace shell