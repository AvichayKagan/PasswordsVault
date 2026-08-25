#ifdef _WIN32


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include "sodium.h"


int input(char *buffer, size_t max_len, int hide_char) {
    size_t idx = 0;
    char *ch;
    int status;
    int error = 0;

    // cannot palce sesitive info on the stack, must use sodium_malloc
    ch = sodium_malloc(1);
    if (ch == NULL) return -1;

    while (1) {
        *ch = _getch();

        // Handle arrow and funciton keys (discard them)
        if (*ch == 0 || *ch == 224) {
            _getch();
            continue;
        }

        // Stop on enter
        if (*ch == '\n' || *ch == '\r') {
            break;
        }

        // Handle backspace
        if (*ch == '\b') {
            if (idx > 0) {
                idx--;
                // Move cursor back, erase asterisk with space, move cursor back again
                printf("\b \b");
                fflush(stdout);
            }
        }
        // Handle standard printable ASCII characters
        else if (*ch >= 32 && *ch <= 126 && idx < max_len - 1) {
            buffer[idx++] = *ch;
            putchar(hide_char ? "*" : *ch);
            fflush(stdout);
        }
    }

    buffer[idx] = '\0'; // Null-terminate the string

    sodium_free(ch);
    return 0;
}


int key_press() {
    // ...
    return -1;
}


#endif // _WIN32