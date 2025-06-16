#pragma once
#include <nt_internals.hpp>
#include <ntifs.h>
#include <cstdint>
#include "memory.hpp"
#include "utils.hpp"

namespace callbacks {
    enum callback_type
    {
        ProcessObject,
        ThreadObject
    };

    struct callback_information
    {
        memory::module::module_information mi;
        bool pre_operation;
        std::uint8_t padding[7];
        std::uintptr_t callback_address;
    };

    _OB_CALLBACK_ENTRY* get_object_callback_entry(callback_type callback_type);

    template<typename CallbackFoundOperation>
    void enumerate_object_callbacks(callback_type callback_type, CallbackFoundOperation callback_found)
    {
        auto entryHead = get_object_callback_entry(callback_type);
        if (!entryHead) 
        {
            return;
        }
        auto entryBegin = reinterpret_cast<_OB_CALLBACK_ENTRY*>(entryHead->ListEntry.Flink);

        callback_information* cb =
            reinterpret_cast<callback_information*>(
                ExAllocatePoolZero(PagedPool, sizeof(callback_information) * 256, 'cbFF'));
        int count = 0;

        while (entryBegin != entryHead)
        {
            if (entryBegin->PostOperation)
            {
                memory::module::region_belongs_to(reinterpret_cast<std::uintptr_t>(entryBegin->PostOperation), cb[count].mi);
                cb[count].callback_address = reinterpret_cast<std::uintptr_t>(entryBegin->PostOperation);
                cb[count].pre_operation = false;
                count++;
            }

            if (entryBegin->PreOperation)
            {
                memory::module::region_belongs_to(reinterpret_cast<std::uintptr_t>(entryBegin->PreOperation), cb[count].mi);
                cb[count].callback_address = reinterpret_cast<std::uintptr_t>(entryBegin->PreOperation);
                cb[count].pre_operation = true;
                count++;
            }

            entryBegin = reinterpret_cast<_OB_CALLBACK_ENTRY*>(entryBegin->ListEntry.Flink);
        }

        callback_found(cb, count);
    }

    static void NoOpOperationCallback(
        PVOID RegistrationContext,
        PVOID OperationInformation
    )
    {
		ang_debug("NoOpOperationCallback called with RegistrationContext: %p, OperationInformation: %p\n",
			RegistrationContext, OperationInformation);
    }

}