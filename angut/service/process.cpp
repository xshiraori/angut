#include <process.hpp>
#include <memory.hpp>
#include <utils.hpp>

using CurrentVer = memory::CONSTANTS::WIN10;

namespace process {
	
    // typical handle creation for a process is as follows:
	// OpenProcess -> NtOpenProcess (UM) -> NtOpenProcess (KM) -> PsOpenProcess -> ObOpenObjectByPointer -> ObpCreateHandle -> ExCreateHandle
    // ObpCreateHandle is responsible for executing the object callbacks, therefore by crafting a fresh handle, we bypass this check
    // some anti-cheats are known to enumerate this table and check for handles that has insane access rights
    INSECURE_CODE
    NTSTATUS create_handle_for_user(
		PEPROCESS caller,
		PEPROCESS target,
		ACCESS_MASK desired_access,
		PHANDLE out_handle
	) {
		
        PHANDLE_TABLE       handle_table;
        PHANDLE_TABLE_ENTRY new_entry;
        _EX_HANDLE new_handle;

        if (!caller || !target || !out_handle)
        {
            return STATUS_INVALID_PARAMETER;
        }

        *out_handle = NULL;

		handle_table = *reinterpret_cast<PHANDLE_TABLE*>(OFFSET_TO(caller, CurrentVer::EPROCESS_TO_HANDLE_TABLE));
        if (!handle_table)
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = ObfReferenceObject(target);
        if (!NT_SUCCESS(status)) 
        {
            return status;
        }

        if (!memory::CONSTANTS::UNDOCUMENTED::ExpAllocateHandleTableEntry) 
        {
            ObfDereferenceObject(target);
            return STATUS_NOT_FOUND;
        }
        
        new_entry = memory::CONSTANTS::UNDOCUMENTED::ExpAllocateHandleTableEntry(handle_table, &new_handle);

        if (!new_entry) 
        {
            ObfDereferenceObject(target); 
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ExAcquirePushLockExclusive(&handle_table->HandleTableLock);

        new_entry->Unlocked = 1;  
        new_entry->RefCnt = 0;       
        new_entry->Attributes = 0;

        std::uint64_t object_header = reinterpret_cast<uintptr_t>(target) - CurrentVer::OBJECT_TO_HEADER;
        std::uint64_t encoded_pointer = (object_header >> 4) & REFCOUNT_MASK;

        new_entry->ObjectPointerBits = encoded_pointer;
        new_entry->GrantedAccessBits = desired_access & PROCESS_ALL_ACCESS;

        ExReleasePushLockExclusive(&handle_table->HandleTableLock);

        if (!new_handle.Value)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

		auto object_header_ptr = reinterpret_cast<_OBJECT_HEADER*>(object_header);
        InterlockedIncrement64(&object_header_ptr->HandleCount);

        *out_handle = new_handle.Value;
        return STATUS_SUCCESS;
	}

	NTSTATUS get_process_base(std::uint32_t process_id, std::uint64_t& base_address) 
    {
		PEPROCESS process = nullptr;

		NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(process_id), &process);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

		ang_debug("Process ID: %u, Process Name: %s\n", process_id, PsGetProcessImageFileName(process));

        base_address = reinterpret_cast<std::uintptr_t>(PsGetProcessSectionBaseAddress(process));
        
		ObDereferenceObject(process);
		return STATUS_SUCCESS;
	}
}
