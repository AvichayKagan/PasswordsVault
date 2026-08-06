#ifndef _WIN32


#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>


static inline int safe_input(char *buffer, size_t max_len);

static inline int unsafe_input(char *buffer, size_t max_len);


int input(void *target, size_t len, int is_safe) {
    if (target == NULL || len == 0) return -1;

    switch (is_safe) {
        case 0:
            return unsafe_input(target, len);
        default:
            return safe_input(target, len);
    }
}


static inline int safe_input(char *buffer, size_t max_len) {
    struct termios oldt, newt;
    size_t idx = 0;
    char ch;
    int status;
    int error = 0;

    // 1. Save original terminal settings and clone them
    if (tcgetattr(STDIN_FILENO, &oldt)) return unsafe_input(buffer, max_len);
    newt = oldt;

    // 2. Disable canonical mode (ICANON) and echo (ECHO)
    newt.c_lflag &= ~(ICANON | ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt)) return unsafe_input(buffer, max_len);

    // 3. Read characters one by one
    while (1) {

        status = read(STDIN_FILENO, &ch, 1);
        if (status == -1) {
            error = -1;
            break;
        }
        else if (status == 0) break;

        // Stop on Enter key (Newline or Carriage Return)
        if (ch == '\n' || ch == '\r') {
            break;
        }

        // Handle Backspace / Delete (ASCII 127 or 8)
        if (ch == 127 || ch == '\b') {
            if (idx > 0) {
                idx--;
                // Move cursor back, erase asterisk with space, move cursor back again
                write(STDOUT_FILENO, "\b \b", 3);
            }
        }
        // Handle standard printable ASCII characters
        else if (ch >= 32 && ch <= 126 && idx < max_len - 1) {
            buffer[idx++] = (char)ch;
            write(STDOUT_FILENO, "*", 1);
        }
    }

    buffer[idx] = '\0'; // Null-terminate the string

    // 4. Always restore original terminal settings before exiting function
    if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt)) return -1;
    write(STDOUT_FILENO, "\n", 1);

    return error;
}



static inline int unsafe_input(char *buffer, size_t max_len) {
    int ch;
    size_t len;

    if (fgets(buffer, max_len, stdin) != NULL) {
        len = strcspn(buffer, "\n");

        if (buffer[len] == '\n') {
            // Newline found: replace it with null terminator
            buffer[len] = '\0';
            return 0;
        }
         
        if (feof(stdin)) {
            return 0;
        }
        else {
            // Newline NOT found: input exceeded max_len - 1!
            // Flush leftover characters until newline or EOF to clear stdin
            while ((ch = getchar()) != '\n' && ch != EOF);
            return 1;
        }
    }

    if (feof(stdin)) {
        buffer[0] = '\0';
        return 0; // EOF reached with 0 bytes read
    }

    return -1;
}

#else
typedef int dummy_windows_guard;
#endif // _WIN32