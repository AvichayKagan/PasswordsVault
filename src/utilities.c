#include "utilities.h"

int read_string(char *buffer, int max_size) {
    if (fgets(buffer, max_size, stdin) == NULL) {
        return -1; // Read error or EOF
    }

    size_t len = strlen(buffer);

    // Check 1: Did it find a newline? 
    // This means the input was SHORTER than the buffer.
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0'; // Strip the newline
        return 0; // Success
    }

    // Check 2: There is NO newline in the buffer.
    // This means fgets() hit its limit (max_size - 1). 
    // Let's inspect the very next character waiting in stdin to see what happened next.
    int next_char = getchar();

    if (next_char == '\n' || next_char == EOF) {
        // The next char IS a newline. That means the user's input 
        // matched the buffer size to the exact absolute limit. No overflow!
        return 0; // Success
    } else {
        // The next char is NOT a newline. That means there are extra characters 
        // still waiting in stdin. The user typed too much!
        
        // Flush out the rest of the overflowing line so it doesn't mess up future inputs:
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        
        return 1; // Error: Input too long
    }
}




int load_file_to_buffer(FILE *file, Data *buffer, int start_at) {
    unsigned long long file_size = get_file_size(file);
    fseek(file, start_at, SEEK_SET);

    if (file_size < 0) {
        perror("Failed to determine file size");
        return -1;
    }

    // 3. Allocate a dynamic buffer of unsigned chars to hold the raw bytes
    buffer->data = sodium_malloc(file_size*1.5);
    if (buffer == NULL) {
        fprintf(stderr, "Fatal Error: Memory allocation failed.\n");
        return -1;
    }

    // 4. Read the entire file bit-for-bit into the buffer
    size_t bytes_read = fread(buffer->data, 1, file_size - (unsigned long long)start_at, file);
    if (bytes_read != (size_t)(file_size - start_at)) {
        sodium_free(buffer->data);
        return -1;
    }

    buffer->len = bytes_read;

    return 0; // Returns pointer to the raw byte buffer
}

unsigned long long get_file_size(FILE *file) {
    // 1. Seek to the end of the file
    if (fseek(file, 0, SEEK_END) != 0) {
        return -1;
    }

    // 2. Get the size
    unsigned long long size = ftell(file);
    if (size < 0) {
        return -1;
    }
    // 3. Reset back to the beginning (or wherever you need it)
    rewind(file); // Same as fseek(file, 0, SEEK_SET);

    return size;
}