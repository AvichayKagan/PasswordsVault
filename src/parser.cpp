#include <vector>
#include "parser.hpp"
#include "shell.hpp"

namespace shell {
namespace {

class Tokens {
    private:
        std::vector<std::pair<crypto::SafeVar, bool>> tokens;

        void slice(unsigned char *start, unsigned char *end) {
            bool flag = 0;
            if (*start == '-') {
                start = skip_space(++start);
                flag = true;
            }
            if (start >= end) return;
            crypto::SafeVar token(end - start + 1);
            std::memcpy(token.get(), start, end - start);
            token.get()[end - start] = '\0';
            tokens.push_back({std::move(token), flag});
        }

        unsigned char *skip_space(unsigned char *start) {
            while(std::isspace(*start)) start++;
            return start;
        }

        unsigned char *skip_word(unsigned char *start) {
            if (*start == '-') start = skip_space(++start);
            while(*start != '\0' && !std::isspace(*start)) start++;
            return start;
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

            start = skip_space(end);
            if (*start == '\0') return;
            if (*start != '-') {
                end = get_first_flag(skip_word(start));
                while (std::isspace(*(--end)));
                end++;
            }
            else end = skip_word(start);

            while (*start != '\0') {
                slice(start, end);
                start = skip_space(end);
                end = skip_word(start);
            }
        }

        using iterator = std::vector<std::pair<crypto::SafeVar, bool>>::iterator;

        iterator begin() { return tokens.begin(); }
        iterator end() { return tokens.end(); }

};


size_t get_code(const char *name) {
    for (int code = 0; Shell::commands[code].name != nullptr; code++) {
        if (!std::strcmp(Shell::commands[code].name, name)) return code;
    }
    return -1;
}

const Shell::Flag *get_flag_code(int command_code, const char *name) {
    for (int i = 0; Shell::commands[command_code].flags[i].name != nullptr; i++) {
        if (!std::strcmp(Shell::commands[command_code].flags[i].name, name)) {
            return &Shell::commands[command_code].flags[i];
        }
    }
    return nullptr;
}


} // anonymous namespace


ShellEncoding parse(crypto::SafeVar &instruction) {
    Tokens tokens(instruction);
    instruction.memzero();
    ShellEncoding encoding = {};

    
    Tokens::iterator it = tokens.begin();

    // check for empty instruction
    if (it == tokens.end()) {
        encoding.error = true;
        return encoding;
    }
    

    // take command
    encoding.command = get_code((char*)it->first.get()); // get the code
    if (encoding.command == -1) {
        encoding.error = true;
        std::cerr << "Unrecognized command '" << tokens.begin()->first.get() << "'.\n";
        return encoding;
    }
    it++;

    // check for info flag
    if (it != tokens.end() && it->second && !std::strcmp((char*)it->first.get(), "info")) { // safe to use plain strcmp here?
        encoding.flags = Shell::INFO;
        if (++it != tokens.end()) {
            encoding.error = true;
            std::cerr << "No additional tokens allowed post -info flag.\n";
        }
        return encoding;
    }

    // take the argument
    if (Shell::commands[encoding.command].has_arg) {
        if (it != tokens.end() && !it->second) {
            encoding.arg = crypto::SafeVar(config::max_name_len + 1);
            if (std::strlen((char*)it->first.get()) > config::max_name_len) {
                encoding.error = true;
                std::cerr << "Name '" << (char*)it->first.get() << "' is too long, max allowed naem length is " << config::max_name_len << ".\n";
                return encoding;
            }
            else std::strcpy((char*)encoding.arg.get(), (char*)it->first.get());
            it++;
        }
        else {
            encoding.error = true;
            std::cerr << "Command '" << tokens.begin()->first.get() << "' expects an argument.\n";
            return encoding;
        }
    }

    while (it != tokens.end()) {
        if (it->second) {
            const Shell::Flag *flag = get_flag_code(encoding.command, (char*)it->first.get());
            if (flag == nullptr) {
                encoding.error = true;
                std::cerr << "Unrecognized flag '-" << it->first.get() << "' for command '" << tokens.begin()->first.get() << "'.\n";
                return encoding;
            }
            encoding.flags |= flag->code;
            it++;
            if (flag->has_arg && it != tokens.end() && !it->second) {
                // add flag validity (ie -gen can inly accept number)
                encoding.flag_args.push_back(std::move(it->first));
                it++;
            }
        }
        else {
            encoding.error = true;
            std::cerr << "Too many arguments were given for command '" << tokens.begin()->first.get() << "', (only 1 argument is allowed '" << it->first.get() << "' was given later).\n";
            return encoding;
            it++;
        }
    }

    return encoding;
}

} // namespace shell