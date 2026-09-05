#include <iostream>
#include "vault.hpp"
#include "crypt.hpp"
#include "safe_io.hpp"
#include "parser.hpp"

namespace shell {

class Error : public config::GeneralError {
    public:
        explicit Error(const std::string& message, int errorCode = 1) 
            : config::GeneralError(message, "SHELL", errorCode) {}
    };

class Shell {
    private:
        std::unique_ptr<vault::Vault> vault;
        ShellEncoding encoding;

        // vault user operations
        friend struct Command;
        // sudo
        public:
        void open();
        void add();
        void del();
        void chpass();
        void rename();
        void chmaster();
        // non sudo
        void list();
        void show();
        void exit() { vault.reset(); }
        void help();
        void info();
        void close();


    public:
        static constexpr const char* open_desc     = "Detailed usage instructions for the open command go here.";
        static constexpr const char* close_desc    = "Detailed usage instructions for the close command go here.";
        static constexpr const char* exit_desc     = "Detailed usage instructions for the exit command go here.";
        static constexpr const char* help_desc     = "Detailed usage instructions for the help command go here.";
        static constexpr const char* add_desc      = "Detailed usage instructions for the add command go here.";
        static constexpr const char* list_desc     = "Detailed usage instructions for the list command go here.";
        static constexpr const char* show_desc     = "Detailed usage instructions for the show command go here.";
        static constexpr const char* del_desc      = "Detailed usage instructions for the del command go here.";
        static constexpr const char* info_desc     = "Detailed usage instructions for the info command go here.";
        static constexpr const char* chpass_desc   = "Detailed usage instructions for the chpass command go here.";
        static constexpr const char* rename_desc   = "Detailed usage instructions for the rename command go here.";
        static constexpr const char* chmaster_desc = "Detailed usage instructions for the chmaster command go here.";

        struct Flag {
            const char *name;
            bool has_arg;
        };

        using MethodPtr = void (Shell::*)();
        struct Command {
            const char *name;
            bool allow_close; // does not promise same behaviour in clsoe and open state
            bool has_arg;
            bool sudo;
            MethodPtr method;
            const Flag *flags;
            const char *desc_short;
            const char *desc_long;
        };



        static  constexpr Flag default_flags[] = {
            {"info", false}, 
            {}
        }; 

        static  constexpr Flag add_flags[] = {
            {"info", false}, 
            {"copy", false}, 
            {"gen", true}, 
            {}
        }; 

        static constexpr Command commands[] = {
            // name       allow_close has_args sudo   flags          desc_short                                     desc_long

            {"open",      true,       false,   true,  &shell::Shell::open,     default_flags, "Open and unlock the vault",                   open_desc},
            {"close",     true,       false,   false, &shell::Shell::close,    default_flags, "Close and lock the vault",                    close_desc},
            {"exit",      true,       false,   false, &shell::Shell::exit,     default_flags, "Safely lock the vault and exit the program",  exit_desc},
            {"help",      true,       false,   false, &shell::Shell::help,     default_flags, "Show help and usage information",             help_desc},
            {"add",       false,      true,    true,  &shell::Shell::add,      add_flags,     "Add a new password",                          add_desc},
            {"list",      false,      false,   false, &shell::Shell::list,     default_flags, "List all entry names in the vault",           list_desc},
            {"show",      false,      true,    false, &shell::Shell::show,     default_flags, "Show a password",                             show_desc},
            {"del",       false,      true,    true,  &shell::Shell::del,      default_flags, "Delete a password",                           del_desc},
            {"info",      true,       false,   false, &shell::Shell::info,     default_flags, "Show vault information and status",           info_desc},
            {"chpass",    false,      true,    true,  &shell::Shell::chpass,   default_flags, "Change the password of an existing entry",    chpass_desc},
            {"rename",    false,      true,    true,  &shell::Shell::rename,   default_flags, "Rename an entry",                             rename_desc},
            {"chmaster",  false,      false,   true,  &shell::Shell::chmaster, default_flags, "Change the vault's master password",          chmaster_desc},
            {} // sentinel
        };


        static constexpr size_t max_command_len = []() {
            size_t max_len = 0;
            for (int i = 0; commands[i].name != nullptr; i++) {
                size_t len = std::string_view(commands[i].name).length();
                if (max_len < len) max_len = len;
            }
            return max_len;
        }();

        Shell() {
            if (!safeio::is_interactive_terminal()) throw config::FatalError("The vault can only be run in an interactive terminal.", "IO");
            if (safeio::set_terminal()) throw config::FatalError("Failed to initiate safe terminal.", "IO");

            try {
                vault = std::make_unique<vault::Vault>();
            }
            catch (const vault::Error& e) {
                if (e.code() != vault::InitError) throw;
            }
        };

        ~Shell() { 
            if (safeio::set_terminal()) std::cerr << "Warning: failed to restore terminal settings!\n"; 
        }

        void run();
};

}