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
        void exit();
        void help();
        void info();
        void close();

        
        using MethodPtr = void (Shell::*)();
        static constexpr struct {
            const char *name;
            MethodPtr method;
            bool allow_close; // does not promise same behaviour in clsoe and open state
            bool has_arg;
            bool sudo;
        } commands[] = {
          // name        method ptr    allow_close  has_args  sudo
            {"open",     &Shell::open,     true,    false,    true },
            {"close",    &Shell::close,    true,    false,    false},
            {"exit",     &Shell::exit,     true,    false,    false},
            {"help",     &Shell::help,     true,    false,    false},
            {"add",      &Shell::add,      false,   true,     true },
            {"list",     &Shell::list,     false,   false,    false},
            {"show",     &Shell::show,     false,   true,     false},
            {"del",      &Shell::del,      false,   true,     true },
            {"info",     &Shell::info,     true,    false,    false},
            {"chpass",   &Shell::chpass,   false,   true,     true },
            {"rename",   &Shell::rename,   false,   true,     true },
            {"chmaster", &Shell::chmaster, false,   false,    true },
            {} //sentinel
        };

        static constexpr int max_input_len = []() {
            int max_len = 0;

            for (int i = 0; commands[i].name != nullptr; i++) {
                int new_len = std::string_view(commands->name).length();
                if (max_len < new_len) max_len = new_len;
            }

            return max_len;
        } ()
        + config::max_name_len + config::max_password_len + 1; // 1 for null terminator

    public:
        explicit Shell(vault::Vault &vault) : vault(vault), command(max_input_len), arg(max_input_len) {};

        ~Shell() { vault.close_vault(); }

        Shell(const Shell&) = delete;
        Shell& operator=(const Shell&) = delete;
        Shell(Shell&&) = delete;
        Shell& operator=(Shell&&) = delete;

        void run();
};

}