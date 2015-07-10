#include "dirent.h"
#include <stdlib.h>

#include "searcher.h"
#include "util.h"
#include <fcntl.h>

int scandir(const char *dirname,
struct dirent ***namelist,
	filter_fp filter,
	void *baton) {
	DIR *dirp = NULL;
	struct dirent **names = NULL;
	struct dirent *entry, *d;
	int names_len = 32;
	int results_len = 0;

	dirp = opendir(dirname);
	if (dirp == NULL) {
		goto fail;
	}

	names = (struct dirent**)malloc(sizeof(struct dirent*) * names_len);
	if (names == NULL) {
		goto fail;
	}

	while ((entry = readdir(dirp)) != NULL) {
		if ((*filter)(dirname, entry, baton) == FALSE) {
			continue;
		}
		if (results_len >= names_len) {
			struct dirent **tmp_names = names;
			names_len *= 2;
			names = (struct dirent**)realloc(names, sizeof(struct dirent*) * names_len);
			if (names == NULL) {
				free(tmp_names);
				goto fail;
			}
		}


#if defined _MSC_VER
		size_t s_len = strlen(entry->d_name) + 1;
		d = (struct dirent *)malloc(sizeof(struct dirent) + s_len);
		char *s = (char*)d + sizeof(struct dirent);
		d->d_name = s;
		memcpy(s, entry->d_name, s_len);
#else

#if defined(__MINGW32__) || defined(__CYGWIN__)
		d = malloc(sizeof(struct dirent));
#else
		d = malloc(entry->d_reclen);
#endif

		if (d == NULL) {
			goto fail;
		}
#if defined(__MINGW32__) || defined(__CYGWIN__)
		memcpy(d, entry, sizeof(struct dirent));
#else
		memcpy(d, entry, entry->d_reclen);
#endif


#endif /* _MSC_VER */

		names[results_len] = d;
		results_len++;
	}

	closedir(dirp);
	*namelist = names;
	return results_len;

fail:
	if (dirp) {
		closedir(dirp);
	}

	if (names != NULL) {
		int i;
		for (i = 0; i < results_len; i++) {
			free(names[i]);
		}
		free(names);
	}
	return -1;
}

void search_file(const char *file_full_path, int search_zip_files) {
	int fd;
	off_t f_len = 0;
	char *buf = NULL;
	struct stat statbuf;
	int rv = 0;
	FILE *pipe = NULL;
	char* tmp_file_path = NULL;

	fd = open(file_full_path, O_RDONLY);
	if (fd < 0) {
		/* XXXX: strerror is not thread-safe */
		log_err("Skipping %s: Error opening file: %s", file_full_path, strerror(errno));
		goto cleanup;
	}

	rv = fstat(fd, &statbuf);
	if (rv != 0) {
		log_err("Skipping %s: Error fstat()ing file.", file_full_path);
		goto cleanup;
	}

	//if (opts.stdout_inode != 0 && opts.stdout_inode == statbuf.st_ino) {
	//	log_debug("Skipping %s: stdout is redirected to it", file_full_path);
	//	goto cleanup;
	//}

	if ((statbuf.st_mode & S_IFMT) == 0) {
		log_err("Skipping %s: Mode %u is not a file.", file_full_path, statbuf.st_mode);
		goto cleanup;
	}

	if (statbuf.st_mode & S_IFIFO) {
		log_debug("%s is a named pipe. stream searching", file_full_path);
		pipe = fdopen(fd, "r");
		//search_stream(pipe, file_full_path);
		fclose(pipe);
		goto cleanup;
	}

	f_len = statbuf.st_size;

	if (f_len == 0) {
		log_debug("Skipping %s: file is empty.", file_full_path);
		goto cleanup;
	}

	if (/*!opts.literal && */f_len > INT_MAX) {
		log_err("Skipping %s: pcre_exec() can't handle files larger than %i bytes.", file_full_path, INT_MAX);
		goto cleanup;
	}

#ifdef _WIN32
	{
		HANDLE hmmap = CreateFileMapping(
			(HANDLE)_get_osfhandle(fd), 0, PAGE_READONLY, 0, f_len, NULL);
		buf = (char *)MapViewOfFile(hmmap, FILE_SHARE_READ, 0, 0, f_len);
		if (hmmap != NULL)
			CloseHandle(hmmap);
	}
	if (buf == NULL) {
		FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, (LPSTR)&buf, 0, NULL);
		log_err("File %s failed to load: %s.", file_full_path, buf);
		LocalFree((void *)buf);
		goto cleanup;
	}
#else
	buf = mmap(0, f_len, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		log_err("File %s failed to load: %s.", file_full_path, strerror(errno));
		goto cleanup;
	}
#if HAVE_MADVISE
	madvise(buf, f_len, MADV_SEQUENTIAL);
#elif HAVE_POSIX_FADVISE
	posix_fadvise(fd, 0, f_len, POSIX_MADV_SEQUENTIAL);
#endif
#endif

	

	tmp_file_path = (char *)ag_malloc(MAX_PATH);
	if (search_zip_files) {
		ag_compression_type zip_type = is_zipped(buf, f_len);
		if (zip_type != AG_NO_COMPRESSION) {
			int _buf_len = (int)f_len;
			char *_buf = (char*)decompress(zip_type, buf, f_len, file_full_path, &_buf_len);
			if (_buf == NULL || _buf_len == 0) {
				log_err("Cannot decompress zipped file %s", file_full_path);
				goto cleanup;
			}
			search_buf(_buf, _buf_len, file_full_path, tmp_file_path);
			free(_buf);
			goto cleanup;
		}
	}

	search_buf(buf, f_len, file_full_path, tmp_file_path);

cleanup:

	if (buf != NULL) {
#ifdef _WIN32
		UnmapViewOfFile(buf);
#else
		munmap(buf, f_len);
#endif
	}
	if (fd != -1) {
		close(fd);
	}

	if (tmp_file_path != NULL)
	{
		DeleteFileA(tmp_file_path);
		free(tmp_file_path);
	}
}

void search_buf(char *buf, size_t buf_len,
	const char *dir_full_path, char *tmp_file_path) {
	int binary = -1; /* 1 = yes, 0 = no, -1 = don't know */
	size_t buf_offset = 0;

	//if (opts.search_stream) {
	//	binary = 0;
	//}
	//else if (!opts.search_binary_files) {
	//	binary = is_binary(buf, buf_len);

	//	if (binary) {
	//		log_debug("File %s is binary. Skipping...", dir_full_path);
	//		if (!convert_to_text(&buf, &buf_len, dir_full_path, tmp_file_path))
	//			return;
	//	}
	//}

	binary = is_binary(buf, buf_len);

	if (binary) {
		log_debug("File %s is binary. Convert to text...", dir_full_path);
		if (!convert_to_text(&buf, &buf_len, dir_full_path, tmp_file_path))
			return;
	}
	size_t matches_len = 0;
	match_t *matches;
	size_t matches_size;
	size_t matches_spare;

	//if (opts.invert_match) {
	//	/* If we are going to invert the set of matches at the end, we will need
	//	* one extra match struct, even if there are no matches at all. So make
	//	* sure we have a nonempty array; and make sure we always have spare
	//	* capacity for one extra.
	//	*/
	//	matches_size = 100;
	//	matches = (match_t *)ag_malloc(matches_size * sizeof(match_t));
	//	matches_spare = 1;
	//}
	//else {
	//	matches_size = 0;
	//	matches = NULL;
	//	matches_spare = 0;
	//}
	matches_size = 0;
	matches = NULL;
	matches_spare = 0;

	if (/*!opts.literal && */opts.query_len == 1 && opts.query[0] == '.') {
		matches_size = 1;
		matches = (match_t *)ag_malloc(matches_size * sizeof(match_t));
		matches[0].start = 0;
		matches[0].end = buf_len;
		matches_len = 1;
	}
	else {
		const char *match_ptr = buf;
		strncmp_fp ag_strnstr_fp = get_strstr(opts.casing);

		while (buf_offset < buf_len) {
			match_ptr = ag_strnstr_fp(match_ptr, opts.query, buf_len - buf_offset, opts.query_len, alpha_skip_lookup, find_skip_lookup);
			if (match_ptr == NULL) {
				break;
			}

			if (opts.word_regexp) {
				const char *start = match_ptr;
				const char *end = match_ptr + opts.query_len;

				/* Check whether both start and end of the match lie on a word
				* boundary
				*/
				if ((start == buf ||
					is_wordchar(*(start - 1)) != opts.literal_starts_wordchar) &&
					(end == buf + buf_len ||
					is_wordchar(*end) != opts.literal_ends_wordchar)) {
					/* It's a match */
				}
				else {
					/* It's not a match */
					match_ptr += opts.query_len;
					buf_offset = end - buf;
					continue;
				}
			}

			if (matches_len + matches_spare >= matches_size) {
				/* TODO: benchmark initial size of matches. 100 may be too small/big */
				matches_size = matches ? matches_size * 2 : 100;
				log_debug("Too many matches in %s. Reallocating matches to %zu.", dir_full_path, matches_size);
				matches = (match_t *)ag_realloc(matches, matches_size * sizeof(match_t));
			}

			matches[matches_len].start = match_ptr - buf;
			matches[matches_len].end = matches[matches_len].start + opts.query_len;
			buf_offset = matches[matches_len].end;
			log_debug("Match found. File %s, offset %lu bytes.", dir_full_path, matches[matches_len].start);
			matches_len++;
			match_ptr += opts.query_len;

			if (opts.max_matches_per_file > 0 && matches_len >= opts.max_matches_per_file) {
				log_err("Too many matches in %s. Skipping the rest of this file.", dir_full_path);
				break;
			}
		}
	}
	else {
		int offset_vector[3];
		while (buf_offset < buf_len &&
			(pcre_exec(opts.re, opts.re_extra, buf, buf_len, buf_offset, 0, offset_vector, 3)) >= 0) {
			log_debug("Regex match found. File %s, offset %i bytes.", dir_full_path, offset_vector[0]);
			buf_offset = offset_vector[1];
			if (offset_vector[0] == offset_vector[1]) {
				++buf_offset;
				log_debug("Regex match is of length zero. Advancing offset one byte.");
			}

			/* TODO: copy-pasted from above. FIXME */
			if (matches_len + matches_spare >= matches_size) {
				matches_size = matches ? matches_size * 2 : 100;
				matches = (match_t*)ag_realloc(matches, matches_size * sizeof(match_t));
				log_debug("Too many matches in %s. Reallocating matches to %zu.", dir_full_path, matches_size);
				matches = (match_t *)ag_realloc(matches, matches_size * sizeof(match_t));
			}

			matches[matches_len].start = offset_vector[0];
			matches[matches_len].end = offset_vector[1];
			matches_len++;

			if (opts.max_matches_per_file > 0 && matches_len >= opts.max_matches_per_file) {
				log_err("Too many matches in %s. Skipping the rest of this file.", dir_full_path);
				break;
			}
		}
	}

	if (opts.invert_match) {
		matches_len = invert_matches(buf, buf_len, matches, matches_len);
	}

	if (opts.stats) {
		pthread_mutex_lock(&stats_mtx);
		stats.total_bytes += buf_len;
		stats.total_files++;
		stats.total_matches += matches_len;
		pthread_mutex_unlock(&stats_mtx);
	}

	if (matches_len > 0) {
		if (binary == -1 && !opts.print_filename_only) {
			binary = is_binary(buf, buf_len);
		}
		pthread_mutex_lock(&print_mtx);
		if (opts.print_filename_only) {
			/* If the --files-without-matches or -L option is passed we should
			* not print a matching line. This option currently sets
			* opts.print_filename_only and opts.invert_match. Unfortunately
			* setting the latter has the side effect of making matches.len = 1
			* on a file-without-matches which is not desired behaviour. See
			* GitHub issue 206 for the consequences if this behaviour is not
			* checked. */
			if (!opts.invert_match || matches_len < 2) {
				if (opts.print_count) {
					print_path_count(dir_full_path, opts.path_sep, (size_t)matches_len);
				}
				else {
					print_path(dir_full_path, opts.path_sep);
				}
			}
		}
		else {
			print_file_matches(dir_full_path, buf, buf_len, matches, matches_len);
		}
		pthread_mutex_unlock(&print_mtx);
		opts.match_found = 1;
	}
	else if (opts.search_stream && opts.passthrough) {
		fprintf(out_fd, "%s", buf);
	}
	else {
		log_debug("No match in %s", dir_full_path);
	}

	if (matches_size > 0) {
		free(matches);
	}
}
