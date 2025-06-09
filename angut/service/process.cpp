#include <process.hpp>
#include <memory.hpp>
#include <utils.hpp>

namespace process {
	NTSTATUS create_handle_for_user(
		PEPROCESS caller,
		PEPROCESS target,
		ACCESS_MASK desired_access,
		PHANDLE out_handle
	) {
		
        PHANDLE_TABLE       handle_table;
        PHANDLE_TABLE_ENTRY new_entry;

        PFN_EXPALLOCATEHANDLETABLEENTRY ExpAllocateHandleTableEntry = nullptr;

        ExpAllocateHandleTableEntry = (PFN_EXPALLOCATEHANDLETABLEENTRY)(0xfffff8023668bdf0);
        if (!caller || !target || !out_handle)
        {
            return STATUS_INVALID_PARAMETER;
        }
        *out_handle = NULL;

        handle_table = *(PHANDLE_TABLE*)((PUCHAR)caller + memory::OFFSETS::WIN10::EPROCESS_TO_HANDLE_TABLE);
        if (!handle_table)
        {
            return STATUS_UNSUCCESSFUL;
        }

        _EX_HANDLE new_handle;
        new_entry = ExpAllocateHandleTableEntry(handle_table, &new_handle);

        ExAcquirePushLockExclusive(&handle_table->HandleTableLock);

        new_entry->Unlocked = 1;  
        new_entry->RefCnt = 1;       
        new_entry->Attributes = 0;

        auto object_address = reinterpret_cast<uintptr_t>(target);
        auto object_header = object_address - 0x30;
        auto encoded_pointer = (object_header >> 4) & 0xFFFFFFFFFFF;

		utils::logger::debug("address: %p and entry %p\n", encoded_pointer, new_entry);

        new_entry->ObjectPointerBits = encoded_pointer;
        new_entry->GrantedAccessBits = desired_access & 0x01FFFFFF; 

        ExReleasePushLockExclusive(&handle_table->HandleTableLock);

        utils::logger::debug("handle hijacked %x\n", new_handle.Value);

        if (new_handle.Value == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        *out_handle = new_handle.Value;
        return STATUS_SUCCESS;
	}
}