#ifndef _WIN32


#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include "sodium.h"


static int ret(int code, char *ch) {
    sodium_free(ch);
    return code;
}

int input(unsigned char *buffer, size_t max_len, int hide_char) {
    struct termios oldt, newt;
    size_t idx = 0;
    char *ch;
    int status;
    int error = 0;

    // cannot palce sesitive info on the stack, must use sodium_malloc
    ch = sodium_malloc(1);
    if (ch == NULL) return -1;

    // Save original terminal settings and clone them
    if (tcgetattr(STDIN_FILENO, &oldt)) return ret(-1, ch);
    newt = oldt;

    // Disable canonical mode (ICANON) and echo (ECHO)
    newt.c_lflag &= ~(ICANON | ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt)) ret(-1, ch);

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

    // restore original terminal settings before exiting function
    if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt)) ret(-1, ch);
    write(STDOUT_FILENO, "\n", 1);

    return ret(error, ch);
}


int key_press() {
    struct termios oldt, newt;
    int ch;

    // Save original terminal settings and clone them
    if (tcgetattr(STDIN_FILENO, &oldt)) return -1;
    newt = oldt;

    // modify the terminal
    newt.c_lflag &= ~(ICANON | ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt)) return -1;

    // grab single character
    ch = getchar();

    // restore original terminal settings before exiting function
    if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt)) return -1;

    return ch;
}

void safe_print_set() {
    // 1. Switch to Alternate Screen Buffer: \033[?1049h
    write(STDOUT_FILENO, "\033[?1049h", 8);
    // 2. Move cursor to top left and clear this new buffer just in case
    write(STDOUT_FILENO, "\033[2J\033[H", 7);
}

void safe_print_destroy() {
    write(STDOUT_FILENO, "\033[?1049l", 8);
}


#endif // _WIN32