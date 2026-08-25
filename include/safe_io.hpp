#pragma once

#include <iostream>


namespace safeio {

extern "C" {
    int input(unsigned char *buffer, size_t max_len, int hide_char);

    int key_press();

    void safe_print_set();

    void safe_print_destroy();
}

class Destroy {};
class Endl {};
class Flush {};

class OutStream {
    private:
        bool is_active = false;

    public:
        template <typename T>
        OutStream& operator<<(const T& data) {
            if (!is_active) {
                safe_print_set();
                is_active = true;
            }
            std::cout << data;

            return *this;
        }

        OutStream& operator<<(const Flush&) {
            if (is_active) std::cout << std::flush;

            return *this;
        }

        OutStream& operator<<(const Endl&) {
            if (is_active) std::cout << std::endl;

            return *this;
        }
        
        OutStream& operator<<(const Destroy&) {
            if (is_active) {
                std::cout << std::flush;
                safe_print_destroy();
                is_active = false;
            }

            return *this;
        }
};

inline Destroy destroy;
inline Endl endl;
inline Flush flush;
inline OutStream cout;


}