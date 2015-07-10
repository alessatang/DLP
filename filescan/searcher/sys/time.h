#ifndef wincompat_sys_time_h
#define wincompat_sys_time_h

#include <windows.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct timezone
{
  int  tz_minuteswest; /* minutes W of Greenwich */
  int  tz_dsttime;     /* type of dst correction */
};

int gettimeofday(struct timeval * tp, struct timezone * tzp);

#ifdef __cplusplus
}
#endif

#endif
