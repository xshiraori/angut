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

    void handle_memory_write_request(memory_copy_request req, long& err)
    {
        PEPROCESS  targetProcess = nullptr;
        err = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(UIntToPtr(req.ProcessId)),
            &targetProcess
        );

        if (!NT_SUCCESS(err)) {
            return;
        }

        err = memory::process::write_memory(IoGetCurrentProcess(), req.Buffer, targetProcess, req.Address, req.Size);
        ObDereferenceObject(targetProcess);
    }

    void handle_memory_read_request(memory_copy_request req, long& err)
    {
        PEPROCESS  targetProcess = nullptr;
        err = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(UIntToPtr(req.ProcessId)),
            &targetProcess
        );

        if (!NT_SUCCESS(err)) {
            return;
        }

        err = memory::process::read_memory(targetProcess, req.Address, IoGetCurrentProcess(), req.Buffer, req.Size);
        ObDereferenceObject(targetProcess);
    }
}