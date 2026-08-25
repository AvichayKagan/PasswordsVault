#pragma once

#include <iostream>
#include <unistd.h>


namespace safeio {

extern "C" {
    int input(unsigned char *buffer, size_t max_len, int hide_char);

    int key_press();
}

class destroy {
public:
    const char *message = nullptr;
    destroy() = default;
    destroy(const char* _message) :message(_message) {}
};
class Endl {};
class Flush {};

class OutStream {
    private:
        bool is_active = false;
        size_t line_count = 0;

    public:
        // catch C-strings
        OutStream& operator<<(const char *str) {
            if (str != nullptr) {
                for (int i = 0; str[i] != '\0'; i++) {
                    if (str[i] == '\n') line_count++;
                }
                std::cout << str;
            }
            is_active = true;

            return *this;
        }

        // catch std::string
        OutStream& operator<<(const std::string& str) {
            for (char c : str) {
                if (c == '\n') line_count++;
            }
            is_active = true;

            std::cout << str;

            return *this;
        }

        // catch single char
        OutStream& operator<<(char ch) {
            if (ch == '\n') line_count++;
            is_active = true;

            std::cout << ch;

            return *this;
        }

        template <typename T>
        OutStream& operator<<(const T& str) {
            is_active = true;

            std::cout << str;

            return *this;
        }

        OutStream& operator<<(const Flush&) {
            if (is_active) std::cout << std::flush;

            return *this;
        }

        OutStream& operator<<(const Endl&) {
            if (is_active) {
                std::cout << std::endl;
                line_count++;
            }

            return *this;
        }
        
        OutStream& operator<<(const destroy& obj) {
            if (is_active) {
                // delete the printed data
                if (line_count > 0) std::cout << "\033[" << line_count << "A";
                std::cout << "\r\033[J";

                // print the message and flush
                if (obj.message != nullptr) {
                    std::cout << obj.message << std::endl;
                }
                else std::cout << std::flush;

                is_active = false;
                line_count = 0;
            }

            return *this;
        }
};

inline Endl endl;
inline Flush flush;
inline OutStream cout;

}