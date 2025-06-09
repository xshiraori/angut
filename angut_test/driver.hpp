#pragma once

#include <windows.h>
#include <cstdint>
#include <iostream>

enum CallbackType
{
    ProcessObject,
    ThreadObject
};

#pragma pack(push, 8)  // Ensure 8-byte alignment to match kernel structures
struct enumerate_callbacks_request
{
    CallbackType callback_type;
    uint32_t padding;  // Explicit padding for alignment
};

struct module_information
{
    char module_name[256];
    std::uint64_t base;
    std::uint64_t size;
};

struct callback_information
{
    module_information mi;
    bool pre_operation;
    std::uint8_t padding[7];
    std::uintptr_t callback_address;
};

struct enumerate_callbacks_response
{
    std::uint64_t count;
    callback_information entries[];
};

struct patch_callback_request
{
    CallbackType callback_type;
    std::uintptr_t callback_address;
};

struct create_user_handle_request
{
    std::uint32_t processId;
    ACCESS_MASK desiredAccess;
};

struct create_user_handle_response
{
    HANDLE handle;
};

#pragma pack(pop)

// Updated driver.hpp - add error checking
namespace utils::driver {
    HANDLE hDriver = nullptr;

    struct MEMORY_OPERATION {
        ULONG   ProcessId;
        PVOID   Address;
        PVOID   Buffer;
        SIZE_T  Size;
    };

#define IOCTL_READ_PROCESS_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUMERATE_DRIVERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUMERATE_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PATCH_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DELETE_CALLBACK_PATCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATE_MANUAL_HANDLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

    bool init()
    {
        hDriver = CreateFileW(
            L"\\\\.\\angut",
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hDriver == INVALID_HANDLE_VALUE)
        {
            printf("Failed to open driver handle. Error: %lu\n", GetLastError());
            return false;
        }

        printf("Successfully opened driver handle: 0x%p\n", hDriver);
        return true;
    }

    template<typename T>
    bool do_ioctl(std::uint32_t ioctl_code, T& data)
    {
        DWORD bytesReturned;
        BOOL result = DeviceIoControl(
            hDriver,
            ioctl_code,
            &data,
            sizeof(data),
            &data,  // Output buffer is same as input for METHOD_BUFFERED
            sizeof(data),
            &bytesReturned,
            nullptr
        );

        if (!result) {
            DWORD error = GetLastError();
            printf("DeviceIoControl failed. Error: %lu (0x%lx)\n", error, error);
            printf("IOCTL Code: 0x%lx\n", ioctl_code);
            printf("Input size: %zu, Expected output size: %zu\n", sizeof(data), sizeof(data));
            printf("Bytes returned: %lu\n", bytesReturned);
            return false;
        }

        printf("DeviceIoControl succeeded. Bytes returned: %lu\n", bytesReturned);
        return true;
    }

    bool do_ioctl(std::uint32_t ioctl_code, void* data, size_t size)
    {
        DWORD bytesReturned;
        BOOL result = DeviceIoControl(
            hDriver,
            ioctl_code,
            data,           // Input buffer
            (DWORD)size,    // Input buffer size
            data,           // Output buffer (same as input for METHOD_BUFFERED)
            (DWORD)size,    // Output buffer size
            &bytesReturned,
            nullptr
        );

        if (!result) {
            DWORD error = GetLastError();
            printf("DeviceIoControl failed. Error: %lu (0x%lx)\n", error, error);
            printf("IOCTL Code: 0x%lx\n", ioctl_code);
            printf("Buffer size: %zu\n", size);
            printf("Bytes returned: %lu\n", bytesReturned);

            switch (error) {
            case ERROR_INVALID_HANDLE:
                printf("Error meaning: Invalid handle\n");
                break;
            case ERROR_INVALID_PARAMETER:
                printf("Error meaning: Invalid parameter\n");
                break;
            case ERROR_INSUFFICIENT_BUFFER:
                printf("Error meaning: Buffer too small\n");
                break;
            case ERROR_MORE_DATA:
                printf("Error meaning: More data available\n");
                break;
            case ERROR_GEN_FAILURE:
                printf("Error meaning: General failure\n");
                break;
            default:
                printf("Error meaning: Unknown error\n");
                break;
            }
            return false;
        }

        printf("DeviceIoControl succeeded. Bytes returned: %lu\n", bytesReturned);
        return true;
    }

    void disconnect()
    {
        if (hDriver && hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
            hDriver = nullptr;
            printf("Driver handle closed\n");
        }
    }
}