#ifndef UTILITIES_H
#define UTILITIES_H

#include <stdio.h>
#include <string.h>
#include "encryption.h"

int read_string(char *buffer, int max_size);


int load_file_to_buffer(FILE *file, Data *buffer, int start_at);

unsigned long long get_file_size(FILE *file);

#endif /* UTILITIES_H */