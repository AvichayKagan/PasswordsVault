#pragma once

#include <stdio.h>


#ifndef _cplusplus
namespace safeIO {
extern "C" {
#endif


int input(unsigned char *buffer, size_t max_len, int hide_char);

int output(void *src, size_t len, int is_safe);


#ifndef _cplusplus
} //extern C
} // namespace safeIO
#endif