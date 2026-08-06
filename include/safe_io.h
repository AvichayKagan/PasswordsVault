#pragma once

#include <stdio.h>


#ifndef _cplusplus
extern "C" {
#endif

int input(void *target, size_t len, int is_safe);

int output(void *src, size_t len, int is_safe);


#ifndef _cplusplus
}
#endif