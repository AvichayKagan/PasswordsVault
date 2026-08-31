#pragma once

#include <iostream>

namespace safeio {

extern "C" {
    int is_interactive_terminal();

    int set_terminal();

    int input(unsigned char *buffer, size_t max_len, int hide_char);

    int safe_write(const char *message);

    int key_press();
}

class SafeTerminal {
public:
    SafeTerminal() {
        if (set_terminal()) throw config::FatalError("Failed to initiate safe terminal.", "IO");
    }

    ~SafeTerminal() {
        if (set_terminal()) std::cerr << "Warning: failed to restore termianl settings.\n";
    }

    SafeTerminal(const SafeTerminal&) = delete;
    SafeTerminal& operator=(const SafeTerminal&) = delete;
    SafeTerminal(SafeTerminal&&) = delete;
    SafeTerminal& operator=(SafeTerminal&&) = delete;
};

class Secret {
public:
    const char *message;
    explicit Secret(const char* _message) :message(_message) {}
    explicit Secret(const unsigned char* _message) :message((char *)_message) {}
};

class Endl {};
class Flush {};
inline Endl endl;
inline Flush flush;

class SafeStream {
    private:
        size_t line_count = 0;
        const char *msg = nullptr;

    public:
        SafeStream() = default;
        explicit SafeStream(const char *_msg) :msg(_msg) {}

        ~SafeStream() {
            // delete the printed data
            if (line_count > 0) std::cout << "\033[" << line_count << "A";
            std::cout << "\r\033[J";

            // print the message and flush
            if (msg != nullptr) {
                std::cout << msg << std::endl;
            }
            else std::cout << std::flush;
        }

        SafeStream(const SafeStream&) = delete;
        SafeStream& operator=(const SafeStream&) = delete;
        SafeStream(SafeStream&&) = delete;
        SafeStream& operator=(SafeStream&&) = delete;

        void set_msg(const char *_msg) { msg = _msg; }
        
        // catch C-strings
        SafeStream& operator<<(const char *str) {
            if (str != nullptr) {
                for (int i = 0; str[i] != '\0'; i++) {
                    if (str[i] == '\n') line_count++;
                }
                std::cout << str;
            }

            return *this;
        }

        // catch std::string
        SafeStream& operator<<(const std::string& str) {
            for (char c : str) {
                if (c == '\n') line_count++;
            }
            std::cout << str;

            return *this;
        }

        // catch single char
        SafeStream& operator<<(char ch) {
            if (ch == '\n') line_count++;
            std::cout << ch;
            return *this;
        }

        template <typename T>
        SafeStream& operator<<(const T& str) {
            std::cout << str;
            return *this;
        }

        
        SafeStream& operator<<(const Secret& str) {
            if (str.message != nullptr) {
                for (int i = 0; str.message[i] != '\0'; i++) {
                    if (str.message[i] == '\n') line_count++;
                }
                std::cout << std::flush;
                safe_write(str.message);
            }
            return *this;
        }

        SafeStream& operator<<(const Flush&) {
            std::cout << std::flush;
            return *this;
        }

        SafeStream& operator<<(const Endl&) {
            std::cout << std::endl;
            line_count++;
            return *this;
        }
};


}