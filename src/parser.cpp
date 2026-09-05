#include <vector>
#include "parser.hpp"

constexpr const char* open_desc     = "Detailed usage instructions for the open command go here.";
constexpr const char* close_desc    = "Detailed usage instructions for the close command go here.";
constexpr const char* exit_desc     = "Detailed usage instructions for the exit command go here.";
constexpr const char* help_desc     = "Detailed usage instructions for the help command go here.";
constexpr const char* add_desc      = "Detailed usage instructions for the add command go here.";
constexpr const char* list_desc     = "Detailed usage instructions for the list command go here.";
constexpr const char* show_desc     = "Detailed usage instructions for the show command go here.";
constexpr const char* del_desc      = "Detailed usage instructions for the del command go here.";
constexpr const char* info_desc     = "Detailed usage instructions for the info command go here.";
constexpr const char* chpass_desc   = "Detailed usage instructions for the chpass command go here.";
constexpr const char* rename_desc   = "Detailed usage instructions for the rename command go here.";
constexpr const char* chmaster_desc = "Detailed usage instructions for the chmaster command go here.";

constexpr Flag default_flags[] = {
    {"info", false}, 
    {}
}; 

constexpr Flag add_flags[] = {
    {"info", false}, 
    {"copy", false}, 
    {"gen", true}, 
    {}
}; 


constexpr Command commands[] = {
    // name       allow_close has_args sudo   flags          desc_short                                     desc_long

    {"open",      true,       false,   true,  default_flags, "Open and unlock the vault",                   open_desc},
    {"close",     true,       false,   false, default_flags, "Close and lock the vault",                    close_desc},
    {"exit",      true,       false,   false, default_flags, "Safely lock the vault and exit the program",  exit_desc},
    {"help",      true,       false,   false, default_flags, "Show help and usage information",             help_desc},
    {"add",       false,      true,    true,  add_flags,     "Add a new password",                          add_desc},
    {"list",      false,      false,   false, default_flags, "List all entry names in the vault",           list_desc},
    {"show",      false,      true,    false, default_flags, "Show a password",                             show_desc},
    {"del",       false,      true,    true,  default_flags, "Delete a password",                           del_desc},
    {"info",      true,       false,   false, default_flags, "Show vault information and status",           info_desc},
    {"chpass",    false,      true,    true,  default_flags, "Change the password of an existing entry",    chpass_desc},
    {"rename",    false,      true,    true,  default_flags, "Rename an entry",                             rename_desc},
    {"chmaster",  false,      false,   true,  default_flags, "Change the vault's master password",          chmaster_desc},
    {} // sentinel
};


namespace {

class Tokens {
    private:
        std::vector<crypto::SafeVar> tokens;


        void slice(unsigned char *start, unsigned char *end) {
            crypto::SafeVar token(end - start + 1);
            std::memcpy(token.get(), start, end - start);
            token.get()[end - start + 1] = '\0';
            tokens.push_back(std::move(token));
        }

        unsigned char *skip_space(unsigned char *start) {
            while(std::isspace(*start)) start++;
            return start;
        }

        unsigned char *skip_word(unsigned char *start) {
            while(*start != '\0' && !std::isspace(*start)) start++;
            return --start;
        }

        unsigned char *get_first_flag(unsigned char *start) {
            while(*start != '\0' && *start != '-') start++;
            return start;
        }
        
    public:
        Tokens(crypto::SafeVar instruction) {
            enum {IN, OUT};
            int state = OUT;

            unsigned char *start = skip_space(instruction.get());
            unsigned char *end = skip_word(start);
            slice(start, end);

            start = skip_space(++end);
            end = get_first_flag(start);
            if (*end != '\0' && end != start){
                while (std::isspace(*(--end)));
                slice(start, end);
            }


            while (start != '\0') {
                start = skip_space(++end);
                end = skip_word(start);
                slice(start, end);
            }
        }

        using iterator = std::vector<crypto::SafeVar>::iterator;

        iterator begin() { return tokens.begin(); }
        iterator end() { return tokens.end(); }

};


size_t get_code(const char *name) {
    for (int code = 0; commands[code].name != nullptr; code++) {
        if (!std::strcmp(commands[code].name, name)) return code;
    }
    return -1;
}

size_t get_flag_code(const Flag*, const char *name) {
    for (int code = 0; commands[code].name != nullptr; code++) {
        if (!std::strcmp(commands[code].name, name)) return ((size_t)1 << code);
    }
    return -1;
}


}


ShellEncoding parse(crypto::SafeVar &&instruction) {
    Tokens tokens(std::move(instruction));
    ShellEncoding encoding;

    Tokens::iterator it = tokens.begin();
    
    encoding.command = get_code((char*)it->get()); // get the code
    it++;

    // get the arg
    encoding.arg = crypto::SafeVar(config::max_name_len);
    std::strcpy((char*)encoding.arg.get(), (char*)it->get());
    it++;

    for (; it != tokens.end(); it++) {
        encoding.flags |= get_flag_code(commands[encoding.command].Flags, (char*)it->get());

        
    }



}