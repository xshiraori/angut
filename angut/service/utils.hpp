#pragma once
#include <cstdint>
#include <ntifs.h>
#include <stdarg.h>
#include <ntstrsafe.h> 

namespace utils::misc {
	using driver_enumerate_callback = bool(const char* driver_name, std::uintptr_t image_base, std::uint64_t image_size);

	std::uint64_t get_kernel_base();
}

namespace utils::logger {
    static void debug(
        _In_ PCCH Format,
        ...
    )
    {
        va_list arglist;
        va_start(arglist, Format);
        vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, arglist);
        va_end(arglist);
    }
}