#ifndef SEARCHER_H
#define SEARCHER_H

#include "ignore.h"

#define DLLExport __declspec(dllexport)

typedef struct {
	const ignores *ig;
	const char *base_path;
	size_t base_path_len;
} scandir_baton_t;

typedef int(*filter_fp)(const char *path, const struct dirent *, void *);


int DLLExport scandir(const char *dirname, struct dirent ***namelist, filter_fp filter, void *baton);

void DLLExport search_file(const char *file_full_path, int search_zip_files);

void search_buf(char *buf, size_t buf_len, const char *dir_full_path, char *tmp_file_path);

#endif