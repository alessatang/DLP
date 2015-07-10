/*

    Implementation of POSIX directory browsing functions and types for Win32.

    Author:  Kevlin Henney (kevlin@acm.org, kevlin@curbralan.com)
    History: Created March 1997. Updated June 2003 and July 2012.
    Rights:  See end of file.

*/

#include "dirent.h"
#include <errno.h>
#include <io.h> /* _findfirst and _findnext set errno iff they return -1 */
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef ptrdiff_t handle_type; /* C99's intptr_t not sufficiently portable */

struct DIR
{
    handle_type         handle; /* -1 for failed rewind */
    struct _finddata_t  info;
    struct dirent       result; /* d_name null iff first time */
    char                *name;  /* null-terminated char string */
};

DIR *opendir(const char *name)
{
    DIR *dir = 0;

    if (!name || (0 == name[0])) {
        errno = ENOENT;
        return 0;
    }

    size_t base_len = strlen(name);
    const char *all = /* search pattern must end with suitable wildcard */
        strchr("/\\", name[base_len - 1]) ? "*" : "/*";

    dir = (DIR *) calloc(sizeof *dir, 1);
    dir->name = (char *) malloc(base_len + strlen(all) + 1);
    if (!dir->name) {
        errno = ENOMEM;
        goto Error;
    }

    strcat(strcpy(dir->name, name), all);

    dir->handle = (handle_type) _findfirst(dir->name, &dir->info);
    if (dir->handle == -1) {
        struct stat stat_buf = { 0 };
        int res = stat(name, &stat_buf);
        if (-1 == res) {
            errno = ENOENT;
            goto Error;
        }
        errno = ENOTDIR;
        goto Error;
    }
    dir->result.d_name = 0;
    return dir;
Error:
    if (dir)
        free(dir->name);
    free(dir);
    return 0;
}

int closedir(DIR *dir)
{
    int result = -1;

    if(dir)
    {
        if(dir->handle != -1)
        {
            result = _findclose(dir->handle);
        }

        free(dir->name);
        free(dir);
    }

    if(result == -1) /* map all errors to EBADF */
    {
        errno = EBADF;
    }

    return result;
}

struct dirent *readdir(DIR *dir)
{
    struct dirent *result = 0;

    if(dir && dir->handle != -1)
    {
        if(!dir->result.d_name || _findnext(dir->handle, &dir->info) != -1)
        {
            result         = &dir->result;
            result->d_name = dir->info.name;
        }
    }
    else
    {
        errno = EBADF;
    }

    return result;
}

void rewinddir(DIR *dir)
{
    if(dir && dir->handle != -1)
    {
        _findclose(dir->handle);
        dir->handle = (handle_type) _findfirst(dir->name, &dir->info);
        dir->result.d_name = 0;
    }
    else
    {
        errno = EBADF;
    }
}

#ifdef __cplusplus
}
#endif

/*

    Copyright Kevlin Henney, 1997, 2003, 2012. All rights reserved.

    Permission to use, copy, modify, and distribute this software and its
    documentation for any purpose is hereby granted without fee, provided
    that this copyright and permissions notice appear in all copies and
    derivatives.

    This software is supplied "as is" without express or implied warranty.

    But that said, if there are any problems please get in touch.

*/
