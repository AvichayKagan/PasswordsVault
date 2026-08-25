#ifndef _WIN32


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "sodium.h"


static int ret(int code, char *ch) {
    sodium_free(ch);
    return code;
}

int is_interactive_terminal() {
    return isatty(STDIN_FILENO);
}

int input(unsigned char *buffer, size_t max_len, int hide_char) {
    size_t idx = 0;
    char *ch;
    int status;
    int error = 0;

    // cannot palce sesitive info on the stack, must use sodium_malloc
    ch = sodium_malloc(1);
    if (ch == NULL) return -1;

    // read characters
    while (1) {

        status = read(STDIN_FILENO, ch, 1);
        if (status == -1) {
            error = -1;
            break;
        }
        else if (status == 0) break;

        // Stop on Enter key (Newline or Carriage Return)
        if (*ch == '\n' || *ch == '\r') {
            break;
        }

        // Handle backspace / delete (ASCII 127 or 8)
        if (*ch == 127 || *ch == '\b') {
            if (idx > 0) {
                idx--;
                // Move cursor back, erase asterisk with space, move cursor back again
                write(STDOUT_FILENO, "\b \b", 3);
            }
        }
        // Handle standard printable ASCII characters
        else if (*ch >= 32 && *ch <= 126 && idx < max_len - 1) {
            buffer[idx++] = *ch;
            write(STDOUT_FILENO, hide_char ? "*" : ch, 1);
        }
    }

    buffer[idx] = '\0'; // Null-terminate the string

    write(STDOUT_FILENO, "\n", 1);

    return ret(error, ch);
}

void safe_write(const char *message) {
    // placeholder
    printf("%s", message);
}

int key_press() {
    return getchar();
}

#endif // _WIN32