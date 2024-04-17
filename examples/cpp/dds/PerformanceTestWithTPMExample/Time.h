#ifndef TIME_H_
#define TIME_H_

#if defined(__WIN32__)

#include <windows.h>
inline int64_t getTimeMs()
{
    return timeGetTime();
}

#else

#include <sys/time.h>
inline int64_t getTimeMs()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

#endif

#endif /* TIME_H_ */