#pragma once
#include <callbacks.hpp>
#include <stddef.h>
#include <memory.hpp>

namespace ioctl::handler {

    struct enumerate_callbacks_response
    {
        std::uint64_t count;
        callbacks::callback_information entries[];
    };

    struct enumerate_callbacks_request
    {
        callbacks::callback_type callback_type;
    };

	struct patch_callback_request
	{
        callbacks::callback_type callback_type;
		std::uintptr_t callback_address;
	};

    void handle_callback_enumerate_request(
        enumerate_callbacks_request* req,
        size_t bufferLength,
        NTSTATUS& status,
        ULONG_PTR& info
    )
    {
        auto cbType = static_cast<callbacks::callback_type>(req->callback_type);
        auto resp = reinterpret_cast<enumerate_callbacks_response*>(req);

        RtlZeroMemory(resp, bufferLength);

        size_t headerSize = sizeof(uint64_t);
        size_t entrySize = sizeof(callbacks::callback_information);
        size_t maxEntries = (bufferLength > headerSize)
            ? ((bufferLength - headerSize) / entrySize)
            : 0;

        resp->count = 0;

        auto oneBatch = [&](callbacks::callback_information cbArray[], size_t cbCount)
            {
                for (size_t i = 0; i < cbCount && resp->count < maxEntries; i++)
                {
                    auto& dst = resp->entries[resp->count];
                    auto& src = cbArray[i];

                    RtlStringCchCopyA(dst.mi.module_name,
                        RTL_NUMBER_OF(dst.mi.module_name),
                        src.mi.module_name);

                    dst.mi.base = src.mi.base;
                    dst.mi.size = src.mi.size;
                    dst.callback_address = src.callback_address;
                    dst.pre_operation = src.pre_operation;
                    resp->count++;
                }
            };

        callbacks::enumerate_object_callbacks(cbType, oneBatch);

        size_t bytesWritten = sizeof(uint64_t) + resp->count * entrySize;

        if (resp->count == 0)
        {
            status = STATUS_SUCCESS;
            info = 0;
        }
        else if (resp->count < maxEntries)
        {
            status = STATUS_SUCCESS;
            info = static_cast<ULONG_PTR>(bytesWritten);
        }
        else
        {
            status = STATUS_BUFFER_OVERFLOW;
            info = static_cast<ULONG_PTR>(bytesWritten);
        }
    }

    void handle_patch_callback_request(
       patch_callback_request* req,
       size_t bufferLength,
       NTSTATUS& status,
       ULONG_PTR& info
    )
    {
       auto callback_address = req->callback_address;
       bool callback_found = false;

       auto callback_type = static_cast<callbacks::callback_type>(req->callback_type);

       auto _ = [&](callbacks::callback_information cbArray[], size_t cbCount)
       {
           for (size_t i = 0; i < cbCount; i++)
           {
               if (cbArray[i].callback_address == callback_address)
               {
                   callback_found = true;
               }
           }
       };

       callbacks::enumerate_object_callbacks(callback_type, _);

       if (!callback_found)
       {
           status = STATUS_NOT_FOUND;
           return;
       }

       unsigned char patch_bytes[12] = {
           0x48, 0xB8,                                    // mov rax,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // immediate64 (newAddress)
           0xFF, 0xE0                                     // jmp rax
       };

       // insert the new address into the patch
       *reinterpret_cast<std::uintptr_t*>(&patch_bytes[2]) = reinterpret_cast<std::uintptr_t>(&callbacks::NoOpOperationCallback);

	   utils::logger::debug("Patching callback at address: 0x%llx with new address: 0x%llx\n",
		   callback_address, reinterpret_cast<std::uintptr_t>(&callbacks::NoOpOperationCallback));

       bool success = memory::write_to_read_only_memory(
           reinterpret_cast<PVOID>(callback_address),
           patch_bytes,
           12
       );

       if (success) 
       {
           utils::logger::debug("SUCCESS: Patch applied using write_to_read_only_memory!\n");
           status = STATUS_SUCCESS;
       }
       else 
       {
           utils::logger::debug("ERROR: Failed to apply patch\n");
           status = STATUS_ACCESS_VIOLATION;
       }

       status = STATUS_SUCCESS;
       info = 0;
    }
}

