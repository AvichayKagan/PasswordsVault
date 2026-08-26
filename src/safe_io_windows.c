#ifdef _WIN32


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <windows.h>
#include "sodium.h"

int is_interactive_terminal() {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE || hStdin == NULL) {
        return 0;
    }
    
    DWORD mode = 0;
    // GetConsoleMode will fail if stdin is redirected from a file or a pipe
    return GetConsoleMode(hStdin, &mode);
}

int set_terminal() {
    static int set = 0;

    if (set) reutrn 0;

    // Get the handle to the standard output (the console)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == NULL) return -1;

    // Get the current console mode
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return -1;

    // Enable Virtual Terminal Processing (ANSI escape sequences)
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hOut, dwMode)) return -1;

    set = 1;
    
    return 0;
}

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

void safe_write(const char *message) {
    //
    return;
}


int key_press() {
    return _getch();
}


#endif // _WIN32