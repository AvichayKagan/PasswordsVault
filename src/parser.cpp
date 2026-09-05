#include <vector>
#include "parser.hpp"
#include "shell.hpp"


namespace {

class Tokens {
    private:
        std::vector<crypto::SafeVar> tokens;


        void slice(unsigned char *start, unsigned char *end) {
            crypto::SafeVar token(end - start + 2);
            std::memcpy(token.get(), start, end - start + 1);
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
        Tokens(crypto::SafeVar &instruction) {
            unsigned char *start = skip_space(instruction.get());
            unsigned char *end = skip_word(start);
            slice(start, end);

            start = skip_space(++end);
            end = get_first_flag(start);
            if (*end != '\0' && end != start){
                while (std::isspace(*(--end)));
                slice(start, end);
            }


            while (*start != '\0') {
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
    for (int code = 0; shell::Shell::commands[code].name != nullptr; code++) {
        if (!std::strcmp(shell::Shell::commands[code].name, name)) return code;
    }
    return -1;
}

size_t get_flag_code(const shell::Shell::Flag*, const char *name) {
    for (int code = 0; shell::Shell::commands[code].name != nullptr; code++) {
        if (!std::strcmp(shell::Shell::commands[code].name, name)) return code;
    }
    return -1;
}


}


ShellEncoding parse(crypto::SafeVar &instruction) {
    Tokens tokens(instruction);
    instruction.memzero();
    ShellEncoding encoding;

    Tokens::iterator it = tokens.begin();
    
    encoding.command = get_code((char*)it->get()); // get the code
    it++;

    // get the arg
    if (shell::Shell::commands[encoding.command].has_arg) {
        encoding.arg = crypto::SafeVar(config::max_name_len);
        std::strcpy((char*)encoding.arg.get(), (char*)it->get());
        it++;
    }

    while (it != tokens.end()) {
        size_t flag_code = get_flag_code(shell::Shell::commands[encoding.command].flags, (char*)it->get());
        encoding.flags |= (1 << flag_code);
        it++;

        if (shell::Shell::commands[encoding.command].flags[flag_code].has_arg) {
            encoding.flag_args.push_back(std::move(*it));
            it++;
        }
    }

    return encoding;
}