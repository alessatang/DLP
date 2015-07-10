#ifndef wincompat_unistd_h
#define wincompat_unistd_h

#include "getopt.h"

#ifdef __cplusplus
extern "C"
{
#endif

int getpagesize();

typedef unsigned char uint8_t;

#ifdef __cplusplus
}
#endif

#endif
