#ifdef _WIN32


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>


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
    size_t idx = 0;
    char ch;
    int status;
    int error = 0;

    while (1) {
        ch = _getch();

        // Handle Arrow keys and Function keys (discard them)
        if (ch == 0 || ch == 224) {
            _getch(); // Call it again to throw away the second byte
            continue; // Skip the rest of the loop
        }

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
        if (ch == '\b') {
            if (idx > 0) {
                idx--;
                // Move cursor back, erase asterisk with space, move cursor back again
                printf("\b \b");
                fflush(stdout);
            }
        }
        // Handle standard printable ASCII characters
        else if (ch >= 32 && ch <= 126 && idx < max_len - 1) {
            buffer[idx++] = (char)ch;
            printf("*");
            fflush(stdout);
        }
    }

    buffer[idx] = '\0'; // Null-terminate the string

    return 0;
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
typedef int dummy_posix_guard;
#endif // _WIN32