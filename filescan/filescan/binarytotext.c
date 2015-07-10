#include "binarytotext.h"
#include <string>
#include "util.h"
#include <errno.h>


int convert_to_text(char **buf, size_t *buf_len, const char *dir_full_path,  char *tmp_file_path)
{
	if (tmp_file_path == NULL)
		return 0;

	doctotext_parser_type parserType;
	if (!doctotext_parser_type_by_file_extension(dir_full_path, &parserType))
	{
		log_debug("Cannot detect parser type from the file name %s./n", dir_full_path);
		parserType = DOCTOTEXT_PARSER_AUTO;
	}

	//Create style and extractor params objects
	DocToTextExtractorParams* params = doctotext_create_extractor_params();
	DocToTextFormattingStyle* style = doctotext_create_formatting_style();
	doctotext_formatting_style_set_url_style(style, DOCTOTEXT_URL_STYLE_EXTENDED);
	doctotext_extractor_params_set_verbose_logging(params, 1);
	doctotext_extractor_params_set_formatting_style(params, style);
	doctotext_extractor_params_set_parser_type(params, parserType);

	DocToTextException *exception = NULL;
	DocToTextExtractedData* data = doctotext_process_file_from_buffer(*buf, *buf_len, params, &exception);

	if (data == NULL)
	{
		log_err("Failed to convert binary to text.\n");
		if (exception != NULL)
		{
			size_t errCount = doctotext_exception_error_messages_count(exception);
			for (size_t i = 0; i < errCount; i++)
			{
				log_err("Exception error %d: %s.\n", i, doctotext_exception_get_error_message(exception, i));
			}

			doctotext_free_exception(exception);
		}

		doctotext_free_extractor_params(params);
		doctotext_free_formatting_style(style);
		return 0;
	}
	
	const char *text = doctotext_extracted_data_get_text(data);
	if (text == NULL)
	{
		log_debug("Failed to get the extracted data from the binary file.\n");

		doctotext_free_extracted_data(data);
		doctotext_free_extractor_params(params);
		doctotext_free_formatting_style(style);
		data = NULL;
		params = NULL;
		style = NULL;
		return 0;
	}

	//Create a temp file to save the extracted text

	char lpTmpFilePath[MAX_PATH];
	DWORD dwRet = 0;
	UINT uRet = 0;
	HANDLE hTempFile = INVALID_HANDLE_VALUE;

	dwRet = GetTempPathA(MAX_PATH, lpTmpFilePath);
	if (dwRet > MAX_PATH || (dwRet == 0))
	{
		log_err("GetTempPath failed.\n");
		doctotext_free_extracted_data(data);
		doctotext_free_extractor_params(params);
		doctotext_free_formatting_style(style);
		data = NULL;
		params = NULL;
		style = NULL;
		return 0;

	}

	uRet = GetTempFileNameA(lpTmpFilePath, NULL, 0, (LPSTR)tmp_file_path);
	if (uRet == 0)
	{
		log_err("GetTempFileNameA failed.\n");
		doctotext_free_extracted_data(data);
		doctotext_free_extractor_params(params);
		doctotext_free_formatting_style(style);
		data = NULL;
		params = NULL;
		style = NULL;
		return 0;
	}

	hTempFile = CreateFileA((LPSTR)tmp_file_path,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hTempFile == INVALID_HANDLE_VALUE)
	{
		log_err("Temp file creation failed.\n");
		doctotext_free_extracted_data(data);
		doctotext_free_extractor_params(params);
		doctotext_free_formatting_style(style);
		data = NULL;
		params = NULL;
		style = NULL;
		return 0;
	}

	DWORD dwFilesize = strlen(text) * sizeof(*text);
	DWORD dwSize =0;
	char *pfileContent = (char*)ag_malloc(dwFilesize);
	strcpy(pfileContent, text);

	if (!WriteFile(hTempFile, (LPVOID)text, dwFilesize, &dwSize, NULL))
	{
		log_err("WriteFile failed.\n");

		doctotext_free_extracted_data(data);
		doctotext_free_extractor_params(params);
		doctotext_free_formatting_style(style);
		data = NULL;
		params = NULL;
		style = NULL;
		return 0;
	}
	CloseHandle(hTempFile);
	doctotext_free_extracted_data(data);
	doctotext_free_extractor_params(params);
	doctotext_free_formatting_style(style);
	data = NULL;
	params = NULL;
	style = NULL;

	hTempFile = CreateFileA((LPSTR)tmp_file_path,
		GENERIC_READ|GENERIC_WRITE,
		0,
		NULL,
		OPEN_ALWAYS,
		0,
		NULL);
	if (hTempFile == INVALID_HANDLE_VALUE)
	{
		log_err("Temp file open failed.\n");
		return 0;
	}


	UnmapViewOfFile(*buf);

	//map the temp file

	HANDLE hmmap = CreateFileMapping(
		hTempFile, 0, PAGE_READONLY, 0, dwFilesize, NULL);
	if (hmmap == NULL)
	{
		DWORD err = GetLastError();
		log_err("CreateFileMapping failed. Err = %d.\n", err);
		return 0;
	}
	*buf = (char *)MapViewOfFile(hmmap, FILE_SHARE_READ, 0, 0, dwFilesize);
	if (hmmap != NULL)
		CloseHandle(hmmap);

	CloseHandle(hTempFile);
	if (*buf == NULL) {

		DWORD err = GetLastError();
		FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, *buf, 0, NULL);
		log_err("File %s failed to load: %s.", tmp_file_path, *buf);
		LocalFree((void *)(*buf));
		return 0;
	}

	*buf_len = (size_t)dwFilesize;
	return 1;
}