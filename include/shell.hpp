#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"
#include "safe_io.h"

namespace shell {

class Error : public config::GeneralError {
    public:
        explicit Error(const std::string& message, int errorCode = 1) 
            : config::GeneralError(message, "SHELL", errorCode) {}
    };

class Shell {
    private:

        vault::Vault &vault;
        crypto::SafeVar command;
        crypto::SafeVar arg;

        // internal helpers

        bool parse(unsigned char *input, int *code);

        int get_code();

        void reset() { arg.memzero(); command.memzero(); }

        // vault user operations

       // sudo

        void open() { 
            crypto::SafeVar master_password(config::max_password_len);
            std::cout << "Please enter the master password to continue with this operation: " << std::flush;
            if (safeIO::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
            if (vault.open_vault(master_password)) {
                std::cout << "Vault opened succesfully." << std::endl;
            }
            else std::cout << "Incorrect Master Password. Please type 'open' to try again." << std::endl;
        }

        void add();

        void del();

        // non sudo

        void list() { 
            if (vault.is_empty()) {
                std::cout << "Vault is empty." << std::endl;
            }
            else vault.list_all(); 
        }

        void show();

        void stats() {
            int size = vault.get_size();
            int count = vault.get_count();

            std::cout << "Total passwords in the vault: " << count << std::endl;
            std::cout << "Vault file size is: " << size << " Bytes." << std::endl;
        }

         void close() { 
            vault.close_vault();
            std::cout << "Vault closed succesfully. Use 'open' to reopen it." << std::endl;
        }


        // static constexpr data

        static constexpr const char * const commands[] = {"open", "close", "add", "list", "show", "del", "stats", nullptr};

        static constexpr int max_input_len = []() {
                int max_len = 0;

            for (int i = 0; commands[i] != nullptr; i++) {
                int new_len = std::string_view(*commands).length();
                if (max_len < new_len) max_len = new_len;
            }

            return max_len;
        } ()
        + config::max_name_len + config::max_password_len + 1; // 1 for null terminator

        using MethodPtr = void (Shell::*)();
        static constexpr MethodPtr operations[] = {&Shell::open, &Shell::close, &Shell::add, &Shell::list, &Shell::show, &Shell::del, &Shell::stats};
        static constexpr int commands_has_arg[] = {false, false, true, false, true, true, false};

    public:
        Shell(vault::Vault &vault) : vault(vault), command(max_input_len), arg(max_input_len) {};

        // add destructor? (to clsoe the vault)

        void run();

        void open_public() { 
            crypto::SafeVar master_password(config::max_password_len);
            std::cout << "Please enter the master password to continue with this operation: " << std::flush;
            if (safeIO::input(master_password.get(), config::max_password_len, true)) throw Error("Failed to take the master password from the user.");
            if (vault.open_vault(master_password)) {
                std::cout << "Vault opened succesfully." << std::endl;
            }
            else std::cout << "Incorrect Master Password. Please type 'open' in the Shell to try again." << std::endl;
        }
};

}