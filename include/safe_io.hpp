#pragma once

#include <iostream>

namespace safeio {

extern "C" {
    int is_interactive_terminal();

    int set_terminal();

    int input_c(unsigned char *buffer, size_t max_len, int hide_char);

    int safe_write(const char *message, int error);

    int key_press();
}

class Endl {};
class Flush {};
inline Endl endl;
inline Flush flush;

class SafeStream {
    private:
        static inline size_t line_count;
        std::ostream &stream;

    public:
        SafeStream(std::ostream &stream_) : stream(stream_) {};
        ~SafeStream() { reset(); }
        SafeStream(const SafeStream&) = delete;
        SafeStream& operator=(const SafeStream&) = delete;
        SafeStream(SafeStream&&) = delete;
        SafeStream& operator=(SafeStream&&) = delete;

        void reset() {
            // delete the printed data
            if (line_count > 0) {
                std::cerr << std::flush;
                std::cout << std::flush << "\033[" << line_count << "A";
                std::cout << "\r\033[J" << std::flush;
            }

            line_count = 0;
        }
        
        // catch C-strings
        SafeStream& operator<<(const char *str) {
            if (str != nullptr) {
                for (int i = 0; str[i] != '\0'; i++) {
                    if (str[i] == '\n') line_count++;
                }
                stream << str;
            }

            return *this;
        }

        // catch std::string
        SafeStream& operator<<(const std::string& str) {
            for (char c : str) {
                if (c == '\n') line_count++;
            }
            stream << str;

            return *this;
        }

        // catch single char
        SafeStream& operator<<(char ch) {
            if (ch == '\n') line_count++;
            stream << ch;
            return *this;
        }

        template <typename T>
        SafeStream& operator<<(const T& str) {
            stream << str;
            return *this;
        }

        
        SafeStream& operator<<(const crypto::SafeVar& secret) {
            const char *str = (char *)secret.get();
            if (str != nullptr) {
                for (int i = 0; str[i] != '\0'; i++) {
                    if (str[i] == '\n') line_count++;
                }
                stream << std::flush;
                safe_write(str, &stream == &std::cout ? 0 : 1 );
            }
            return *this;
        }

        SafeStream& operator<<(const Flush&) {
            stream << std::flush;
            return *this;
        }

        SafeStream& operator<<(const Endl&) {
            stream << std::endl;
            line_count++;
            return *this;
        }
};


}