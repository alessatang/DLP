#include <windows.h>
#include <time.h>
#include "unistd.h"
#include "utime.h"

#ifdef __cplusplus
extern "C"
{
#endif

int getpagesize (void)
{
  SYSTEM_INFO system_info;
  GetSystemInfo (&system_info);
  return system_info.dwPageSize;
}


/* TODO: move to sys/time.c */
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME ft;
    static int tzflag = 0;

    if (tv) {
        unsigned __int64 tmp = 0;
        GetSystemTimeAsFileTime(&ft);
        tmp |= ft.dwHighDateTime;
        tmp <<= 32;
        tmp |= ft.dwLowDateTime;

        /* nanoseconds => microseconds */
        tmp /= 10;
        /* convert to Unix epoch (we're Jan 1 1601, unix epoch is
           Jan 1 1970) */
        tmp -= DELTA_EPOCH_IN_MICROSECS;

        /* microseconds => seconds + remaining microseconds */
        tv->tv_sec = (long)(tmp / 1000000UL);
        tv->tv_usec = (long)(tmp % 1000000UL);
    }

    if (tz)
    {
        if (!tzflag) {
          _tzset();
          tzflag++;
        }

        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
