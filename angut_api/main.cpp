#include <Windows.h>
#include <iostream>
#include <fstream>
#include "angut_api.hpp"

void write_into_dat_file(void* data, size_t size)
{
	std::ofstream file("data.dat", std::ios::binary | std::ios::out);
	if (!file)
	{
		std::cerr << "Failed to open data.dat for writing." << std::endl;
		return;
	}
	file.write(reinterpret_cast<const char*>(data), size);
	if (!file)
	{
		std::cerr << "Failed to write data to data.dat." << std::endl;
	}
	file.close();
}

int main()
{
	if (!angut::driver::init())
	{
		std::cerr << "Failed to initialize Angut driver." << std::endl;
		return -1;
	}

	HWND hNotepad = FindWindowA(NULL, "Knight OnLine Client");
	if (!hNotepad)
	{
		std::cerr << "Notepad window not found." << std::endl;
		return -1;
	}

	DWORD processId;
	GetWindowThreadProcessId(hNotepad, &processId);

	angut::service::select_target_process(processId);
	
	DWORD64 baseAddress;
	angut::service::get_process_base(processId, baseAddress);

	if (baseAddress == 0)
	{
		std::cerr << "Failed to get base address for process ID: " << processId << std::endl;
		return -1;
	}

	std::cout << "Base address of Notepad (PID: " << processId << ") is: 0x" << std::hex << baseAddress << std::dec << std::endl;

	void* buffer = malloc(0x100000);
	if (!angut::service::read_memory(buffer, reinterpret_cast<void*>(baseAddress), 0x100000, processId))
	{
		std::cerr << "Failed to read memory from process." << std::endl;
		free(buffer);
		return -1;
	}

	// search for dword 208705
	for (int i = 0; i < 0x100000 - 4; i++)
	{
		if (*reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(buffer) + i) == 208705)
		{
			std::cout << "Found dword 208705 at offset: " << std::hex << i << std::dec << std::endl;
			break;
		}
	}

	write_into_dat_file(buffer, 0x100000);
	return 0;
}