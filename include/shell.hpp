#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"
#include "safe_io.hpp"

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
        bool is_running = true;

        // internal helpers

        bool parse(unsigned char *input, int *code);

        int get_code();

        void reset() { arg.memzero(); command.memzero(); }

        // vault user operations

        // sudo
        void open();
        void add();
        void del();
        void chpass();
        void rename();
        void chmaster();

        // non sudo
        void list();
        void show();
        void exit() { is_running = false; }
        void help();
        void stats();
        void close();


        // static constexpr data (centrelize in struct instead of multiple arrays)
        // add sudo boolean to that and DRY the sudo prompt in the shell implementation calls
        // add allowed when vault is closed boolean

        static constexpr const char * const commands[] = {"open", "close", "exit", "help", "add", "list", "show", "del", "stats", "chpass", "rename", "chmaster", nullptr};
        // remainding are: search
        // flags: gen for passwrod gen and copy flag, update help accordinally

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
        static constexpr MethodPtr operations[] = {&Shell::open, &Shell::close, &Shell::exit, &Shell::help, &Shell::add, &Shell::list, &Shell::show, &Shell::del, &Shell::stats, &Shell::chpass, &Shell::rename, &Shell::chmaster};
        static constexpr int commands_has_arg[] = {false, false, false, false, true, false, true, true, false, true, true, false};

    public:
        Shell(vault::Vault &vault) : vault(vault), command(max_input_len), arg(max_input_len) {};

        ~Shell() { vault.close_vault(); }

        Shell(const Shell&) = delete;
        Shell& operator=(const Shell&) = delete;
        Shell(Shell&&) = delete;
        Shell& operator=(Shell&&) = delete;

        void run();
};

}