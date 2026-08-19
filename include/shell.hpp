#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"

namespace shell {

class Error : public config::GeneralError {
    public:
        using config::GeneralError::GeneralError;
};

class Shell {
    private:

        vault::Vault &vault;
        crypto::SafeVar command;
        crypto::SafeVar arg;


        int get_code();

        void reset() { arg.memzero(); command.memzero(); }

        bool is_open() { 
            if (vault.is_open()) return true;
            std::cout << "Cannot complete the operation, the vault is closed, please type 'open' to open it." << std::endl;
            return false;
        }

        void close() { 
            vault.close_vault();
            std::cout << "Vault closed succesfully. Use 'open' to reopen it." << std::endl;
        }

        void open() { 
            vault.open_vault();
            std::cout << "Vault opened succesfully." << std::endl;
        }

        void add();

        void list() { 
            if (vault.is_empty()) {
                std::cout << "Vault is empty." << std::endl;
            }
            else vault.list_all(); 
        }

        void show();

        void stats() {
            int size = vault.get_size();
            int count = (size - disk::DiskManager::header_size -disk::DiskManager::pre_header_size) / (config::max_name_len + config::max_password_len);

            std::cout << "Total passwords in the vault: " << count << std::endl;
            std::cout << "Vault file size is: " << size << " Bytes." << std::endl;
        }

        
        void del() {
            if (vault.del_password(arg)) {
                std::cout << arg.get() << " has been deleted from the vault." << std::endl;
            }
            else std::cout << "Cannot delete '"<< arg.get() << "' as it doesn't exists in the vault." << std::endl;
        }


        bool parse(unsigned char *input, int *code);



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

        void run();
};

}