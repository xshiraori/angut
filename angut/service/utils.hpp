#pragma once
#include <cstdint>
#include <ntifs.h>
#include <stdarg.h>
#include <ntstrsafe.h> 

#define KERNEL_DEBUGGER2


#define OFFSET_TO(type, offset) \
    (reinterpret_cast<std::uintptr_t>(type) + offset)

// indicates that the code relies on offsets, memory scans or other methods that is dependant on the environment and it may crash the system
// even if the code compiles with success or passes the tests
#define INSECURE_CODE
#define REQUIRES_PATCHGUARD_DISABLED

namespace utils::misc {
	using driver_enumerate_callback = bool(const char* driver_name, std::uintptr_t image_base, std::uint64_t image_size);

	std::uint64_t get_kernel_base();
}

namespace utils::logger {
    static void debug(_In_ PCCH Format, ...)
    {
        va_list arglist;
        va_start(arglist, Format);
#ifdef KERNEL_DEBUGGER
        vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, arglist);
#else
        // Format the message
        char buffer[512];
        int result = _vsnprintf(buffer, sizeof(buffer) - 1, Format, arglist);
        if (result <= 0 || result >= sizeof(buffer) - 1) {
            va_end(arglist);
            return;
        }
        buffer[sizeof(buffer) - 1] = '\0';
        if (strlen(buffer) == 0) {
            va_end(arglist);
            return;
        }

        // Open file
        UNICODE_STRING file_path;
        RtlInitUnicodeString(&file_path, L"\\??\\C:\\driver_log.txt");
        OBJECT_ATTRIBUTES obj_attr;
        InitializeObjectAttributes(&obj_attr, &file_path, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE file_handle;
        IO_STATUS_BLOCK io_status;

        // Create or open file for writing
        NTSTATUS status = ZwCreateFile(
            &file_handle,
            FILE_GENERIC_WRITE,
            &obj_attr,
            &io_status,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,  // Open existing or create new
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            NULL,
            0
        );

        if (NT_SUCCESS(status))
        {
            // Get file size and seek to end
            FILE_STANDARD_INFORMATION fileInfo;
            status = ZwQueryInformationFile(
                file_handle,
                &io_status,
                &fileInfo,
                sizeof(fileInfo),
                FileStandardInformation
            );

            if (NT_SUCCESS(status))
            {
                // Write at the end of file
                ULONG len = (ULONG)strlen(buffer);
                LARGE_INTEGER offset = fileInfo.EndOfFile;

                status = ZwWriteFile(
                    file_handle,
                    NULL,
                    NULL,
                    NULL,
                    &io_status,
                    buffer,
                    len,
                    &offset,  // Specify offset to write at end
                    NULL
                );

                if (NT_SUCCESS(status))
                {
                    ZwFlushBuffersFile(file_handle, &io_status);
                }
            }

            ZwClose(file_handle);
        }
#endif
        va_end(arglist);
    }
}

#define ang_debug(...) utils::logger::debug(__VA_ARGS__)