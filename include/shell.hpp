#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"



class Shell {
    private: 
        Vault &vault;
        std::string command;
        crypto::SafeVar arg;


        int get_code();

        bool is_open() { 
            if (vault.is_open()) return true;
            std::cout << "Cannot complete the operation, the vault is closed, please type 'open' to open it." << std::endl;
            return false;
        }

        void none() {
            std::cout << "Unrecognized command '"<< command << "', did you mean '' ? please type 'help' to list the avalible commands." << std::endl;
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

        void list() { vault.list_all(); }

        void show();

        void stats() {
            int size = vault.get_size();
            int count = (size - DiskManager::header_size -DiskManager::pre_header_size) / (config::max_name_len + config::max_password_len);

            std::cout << "Total passwords in the vault: " << count << std::endl;
            std::cout << "Vault file size is: " << size << " Bytes." << std::endl;
        }

        
        void del() {
            if (vault.del_password(std::move(arg))) {
                std::cout << arg.get() << " has been deleted from the vault." << std::endl;
            }
            else std::cout << "Cannot delete '"<< arg.get() << "' as it doesn't exists in the vault." << std::endl;
        }

        static constexpr const char * const commands[] = {"open", "close", "add", "list", "show", "del", "stats", nullptr};
        using MethodPtr = void (Shell::*)();
        static constexpr MethodPtr operations[] = {&Shell::open, &Shell::close, &Shell::add, &Shell::list, &Shell::show, &Shell::del, &Shell::stats, &Shell::none};

    public:
        Shell(Vault &vault) : vault(vault) {};

        void run();
};