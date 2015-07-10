/* Copyright 2013 the SumatraPDF project authors (see AUTHORS file).
   License: Simplified BSD (see COPYING.BSD) */

/* Note: those are taken from SumatraPDF code */

#include <windows.h>
#include <unknwn.h>
#include <shlwapi.h>
#include <shlobj.h>

#include <stdlib.h>
#include <wchar.h>
#include <string.h>

/* Few most common includes for C stdlib */
#include <assert.h>
#include <float.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <locale.h>

#define APP_NAME_STR L"ag"
#define CRASH_DUMP_FILE_NAME L"ag.dmp"

#define dimof(X)    (sizeof(X)/sizeof((X)[0]))

// auto-free memory for arbitrary malloc()ed memory of type T*
template <typename T>
class ScopedMem
{
    T *obj;
public:
    ScopedMem() : obj(NULL) {}
    explicit ScopedMem(T* obj) : obj(obj) {}
    ~ScopedMem() { free(obj); }
    void Set(T *o) {
        free(obj);
        obj = o;
    }
    T *Get() const { return obj; }
    T *StealData() {
        T *tmp = obj;
        obj = NULL;
        return tmp;
    }
    operator T*() const { return obj; }
};


template <typename T>
inline T *AllocArray(size_t n)
{
    return (T*)calloc(n, sizeof(T));
}

namespace str {

size_t Len(const WCHAR *s)
{
    return s ? wcslen(s) : 0;
}

WCHAR *Dup(const WCHAR *s)
{
    return s ? _wcsdup(s) : NULL;
}

WCHAR *FmtV(const WCHAR *fmt, va_list args)
{
    WCHAR   message[256];
    size_t  bufCchSize = dimof(message);
    WCHAR * buf = message;
    for (;;)
    {
        int count = _vsnwprintf_s(buf, bufCchSize, _TRUNCATE, fmt, args);
        if ((count >= 0) && ((size_t)count < bufCchSize))
            break;
        /* we have to make the buffer bigger. The algorithm used to calculate
           the new size is arbitrary (aka. educated guess) */
        if (buf != message)
            free(buf);
        if (bufCchSize < 4*1024)
            bufCchSize += bufCchSize;
        else
            bufCchSize += 1024;
        buf = AllocArray<WCHAR>(bufCchSize);
        if (!buf)
            break;
    }
    if (buf == message)
        buf = str::Dup(message);

    return buf;
}

WCHAR *Format(const WCHAR *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    WCHAR *res = FmtV(fmt, args);
    va_end(args);
    return res;
}


/* Concatenate 2 strings. Any string can be NULL.
Caller needs to free() memory. */
WCHAR *Join(const WCHAR *s1, const WCHAR *s2, const WCHAR *s3)
{
    if (!s1) s1 = L"";
    if (!s2) s2 = L"";
    if (!s3) s3 = L"";

    return Format(L"%s%s%s", s1, s2, s3);
}

}

namespace path {

bool IsSep(WCHAR c)
{
    return '\\' == c || '/' == c;
}

WCHAR *Join(const WCHAR *path, const WCHAR *fileName)
{
    if (IsSep(*fileName))
        fileName++;
    WCHAR *sepStr = NULL;
    if (!IsSep(path[str::Len(path) - 1]))
        sepStr = L"\\";
    return str::Join(path, sepStr, fileName);
}

    // returns the path to either the %TEMP% directory or a
// non-existing file inside whose name starts with filePrefix
WCHAR *GetTempPath(const WCHAR *filePrefix = NULL)
{
    WCHAR tempDir[MAX_PATH - 14];
    DWORD res = ::GetTempPath(dimof(tempDir), tempDir);
    if (!res || res >= dimof(tempDir))
        return NULL;
    if (!filePrefix)
        return str::Dup(tempDir);
    WCHAR path[MAX_PATH];
    if (!GetTempFileName(tempDir, filePrefix, 0, path))
        return NULL;
    return str::Dup(path);
}

}


namespace dir {

// Return true if a directory already exists or has been successfully created
bool Create(const WCHAR *dir)
{
    BOOL ok = CreateDirectory(dir, NULL);
    if (ok)
        return true;
    return ERROR_ALREADY_EXISTS == GetLastError();
}

}

WCHAR *GetSpecialFolder(int csidl, bool createIfMissing)
{
    if (createIfMissing)
        csidl = csidl | CSIDL_FLAG_CREATE;
    WCHAR path[MAX_PATH];
    path[0] = '\0';
    HRESULT res = SHGetFolderPath(NULL, csidl, NULL, 0, path);
    if (S_OK != res)
        return NULL;
    return str::Dup(path);
}

/* Generate the full path for a filename used by the app in the userdata path. */
/* Caller needs to free() the result. */
WCHAR *AppGenDataFilename(const WCHAR *fileName)
{
    ScopedMem<WCHAR> path;
    /* Use %APPDATA% */
    path.Set(GetSpecialFolder(CSIDL_APPDATA, true));
    if (path) {
        path.Set(path::Join(path, APP_NAME_STR));
        if (path && !dir::Create(path))
            path.Set(NULL);
    }

    if (!path || !fileName)
        return NULL;

    return path::Join(path, fileName);
}

void InstallCrashHandler(const WCHAR *crashDumpPath, const WCHAR *symDir)
{
#if 0
    if (!crashDumpPath)
        return;
    if (!StoreCrashDumpPaths(symDir))
        return;
    if (!BuildSymbolPath())
        return;

    // don't bother sending crash reports when running under Wine
    // as they're not helpful
    bool isWine= BuildModulesInfo();
    if (isWine)
        return;

    BuildSystemInfo();
    // at this point list of modules should be complete (except
    // dbghlp.dll which shouldn't be loaded yet)

    gExeType = DetectExeType();
    // we pre-allocate as much as possible to minimize allocations
    // when crash handler is invoked. It's ok to use standard
    // allocation functions here.
    gCrashHandlerAllocator = new CrashHandlerAllocator();
    gCrashDumpPath = str::Dup(crashDumpPath);
    gDumpEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!gDumpEvent)
        return;
    gDumpThread = CreateThread(NULL, 0, CrashDumpThread, NULL, 0, 0);
    if (!gDumpThread)
        return;
    gPrevExceptionFilter = SetUnhandledExceptionFilter(DumpExceptionHandler);

    signal(SIGABRT, onSignalAbort);
    set_terminate(onTerminate);
    set_unexpected(onUnexpected);
#endif
}

void setup_crash_handler()
{
    ScopedMem<WCHAR> symDir;
    ScopedMem<WCHAR> tmpDir(path::GetTempPath());
    if (tmpDir)
        symDir.Set(path::Join(tmpDir, L"SumatraPDF-symbols"));
    else
        symDir.Set(AppGenDataFilename(L"SumatraPDF-symbols"));

    ScopedMem<WCHAR> crashDumpPath(AppGenDataFilename(CRASH_DUMP_FILE_NAME));
    InstallCrashHandler(crashDumpPath, symDir);
}
