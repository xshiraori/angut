#pragma once
#include <windows.h>
#include <map>
#include <TlHelp32.h>
#include <string>

#undef PROCESSENTRY32
#undef Process32First
#undef Process32Next

namespace utils
{
	std::map<std::string, DWORD> GetProcessList()
	{
		std::map<std::string, DWORD> processList;
		PROCESSENTRY32 pe32;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0)
			return processList;

		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32First(hSnapshot, &pe32))
		{
			CloseHandle(hSnapshot);
			return processList;
		}

		do
		{
			processList[pe32.szExeFile] = pe32.th32ProcessID;
		} while (Process32Next(hSnapshot, &pe32));

		CloseHandle(hSnapshot);
		return processList;
	}
	

	PVOID GetProcessModuleBase(DWORD pid)
	{
		MODULEENTRY32 m32;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, pid);
		if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0)
			return 0;

		m32.dwSize = sizeof(MODULEENTRY32);
		if (!Module32First(hSnapshot, &m32))
		{
			CloseHandle(hSnapshot);
			return 0;
		}

		do
		{
			if (m32.th32ProcessID == pid)
			{
				CloseHandle(hSnapshot);
				return m32.modBaseAddr;
			}
		} while (Module32Next(hSnapshot, &m32));

		return 0;
	}
}