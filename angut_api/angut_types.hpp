#pragma once
#include <cstdint>
#include <Windows.h>

enum callback_type
{
    ProcessObject,
    ThreadObject
};

#pragma pack(push, 8)  // Ensure 8-byte alignment to match kernel structures

struct memory_copy_request
{
    std::uint32_t ProcessId;
    void* Address;
    void* Buffer;
    std::uint64_t Size;
};

struct select_target_process_request
{
    std::uint32_t process_id;
};

typedef memory_copy_request memory_read_request;
typedef memory_copy_request memory_write_request;

struct enumerate_callbacks_request
{
    callback_type callback_type;
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
    callback_type callback_type;
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

struct get_process_info_request
{
    std::uint32_t process_id;
};

struct get_process_info_response
{
    std::uint64_t base_address;
};

struct set_driver_settings_request
{
    bool enable_syscall_hook;
};

#pragma pack(pop)