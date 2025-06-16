#pragma once
#include <ntifs.h>
#include <cstdint>
#include <memory.hpp>

namespace ioctl::handler {

    struct memory_copy_request
    {
        std::uint32_t ProcessId;
        void* Address;
        void* Buffer;
        std::uint64_t Size;
    };

	typedef memory_copy_request memory_read_request;
	typedef memory_copy_request memory_write_request;

    void handle_memory_write_request(memory_write_request* req, size_t bufferLength,
        NTSTATUS& status,
        ULONG_PTR& info)
    {
        PEPROCESS  targetProcess = nullptr;
        status = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(UIntToPtr(req->ProcessId)),
            &targetProcess
        );

        if (!NT_SUCCESS(status)) 
        {
            return;
        }

        status = memory::process::write_memory(IoGetCurrentProcess(), req->Buffer, targetProcess, req->Address, req->Size);
        ObDereferenceObject(targetProcess);
    }

    void handle_memory_read_request(memory_read_request* req, size_t bufferLength,
        NTSTATUS& status,
        ULONG_PTR& info)
    {
        PEPROCESS  targetProcess = nullptr;
        status = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(UIntToPtr(req->ProcessId)),
            &targetProcess
        );

        if (!NT_SUCCESS(status)) 
        {
            return;
        }

        status = memory::process::read_memory(targetProcess, req->Address, IoGetCurrentProcess(), req->Buffer, req->Size);
        ObDereferenceObject(targetProcess);
    }
}