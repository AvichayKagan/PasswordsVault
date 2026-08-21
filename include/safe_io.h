#pragma once

#include <stdio.h>


namespace safeIO {

extern "C" {
    int input(unsigned char *buffer, size_t max_len, int hide_char);

    void safe_print(const char* secure_data);
}


class SafeTerminal {
    private:
        
}


}