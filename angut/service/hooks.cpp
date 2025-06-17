#include <hooks.hpp>
#include <state.hpp>
#include <utils.hpp>
#include <memory.hpp>
#include <process.hpp>
#include "bump.hpp"

decltype(NtQuerySystemInformation)* o_NtQuerySystemInformation = nullptr;
decltype(NtOpenProcess)* o_NtOpenProcess = nullptr;
decltype(NtReadFile)* o_NtReadFile = nullptr;

extern "C" NTSTATUS NtQuerySystemInformation_hook(
    ULONG SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
)
{
    NTSTATUS status = o_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (SystemInformationLength == 0 || !driver_state::get_instance().target_process_id)
    {
        return status;
    }

    auto target_pid = driver_state::get_instance().target_process_id;

    if (SystemInformationClass == SYSTEM_INFORMATION_CLASS_TYPE::SystemHandleInformation)
    {
        auto handleInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(SystemInformation);
        for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++)
        {
            auto handleEntry = &handleInfo->Handles[i];
            if (handleEntry->UniqueProcessId == target_pid && handleEntry->ObjectTypeIndex == 0x7) // 0x7 is the index for process objects
            {
                auto& hs = memory::handle_storage::get_instance();
                if (hs.find<USHORT>(handleEntry->HandleValue))
                {
                    ang_debug("Exfiltrating handle for process %u with handle value %u\n", target_pid, handleEntry->HandleValue);
                    handleEntry->GrantedAccess = 0x1000; // set to PROCESS_QUERY_INFORMATION
                }
            }
        }
    }

    if (SystemInformationClass == SYSTEM_INFORMATION_CLASS_TYPE::SystemExtendedHandleInformation)
    {
        auto handleInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(SystemInformation);
        for (ULONG i = 0; i < handleInfo->HandleCount; i++)
        {
            auto handleEntry = &handleInfo->Handles[i];
            if (reinterpret_cast<std::uint32_t>(handleEntry->UniqueProcessId) == target_pid && handleEntry->ObjectTypeIndex == 0x7) // 0x7 is the index for process objects
            {
                auto& hs = memory::handle_storage::get_instance();
                if (hs.find<PVOID>(handleEntry->HandleValue))
                {
                    ang_debug("Exfiltrating extended handle for process %u with handle value %u\n", target_pid, handleEntry->HandleValue);
                    handleEntry->GrantedAccess = 0x1000; // set to PROCESS_QUERY_INFORMATION
                }
            }
        }
    }

    return status;
}

extern "C" NTSTATUS NtOpenProcess_hook(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
)
{
	if (driver_state::get_instance().target_process_id && reinterpret_cast<uint32_t>(ClientId->UniqueProcess) == driver_state::get_instance().target_process_id)
	{
		ang_debug("Intercepted NtOpenProcess for target process %u with desired access 0x%X\n",
			driver_state::get_instance().target_process_id, DesiredAccess);

		PEPROCESS targetProcess = nullptr;
		PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(ClientId->UniqueProcess), &targetProcess);
        
        auto status = process::create_handle_for_user(
            PsGetCurrentProcess(),
            targetProcess,
            DesiredAccess,
            ProcessHandle
        );

		ObDereferenceObject(targetProcess);
        return status;
	}


	return o_NtOpenProcess(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId
	);
}


static bool get_file_info(HANDLE file_handle)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    PFILE_NAME_INFORMATION fileNameInfo = NULL;
    ULONG bufferSize = sizeof(FILE_NAME_INFORMATION) + (260 * sizeof(WCHAR));

    fileNameInfo = (PFILE_NAME_INFORMATION)ExAllocatePoolWithTag(
        PagedPool,
        bufferSize,
        'FNME'
    );

    if (!fileNameInfo) {
        return false;
    }

    // Query file name information
    status = ZwQueryInformationFile(
        file_handle,
        &ioStatusBlock,
        fileNameInfo,
        bufferSize,
        FileNameInformation
    );
    if (NT_SUCCESS(status)) {
		if (wcsstr(fileNameInfo->FileName, L"Skill_Magic_Main_us.tbl") != NULL) 
        {
			ang_debug("Intercepted file read for Skill_Magic_Main_us.tbl\n");
            return true;
		}
    }

    ExFreePoolWithTag(fileNameInfo, 'FNME');
    return false;
}

LONG ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
    NTSTATUS code = ExceptionInfo->ExceptionRecord->ExceptionCode;
    ang_debug("Exception 0x%08X occurred\n", code);
    return EXCEPTION_EXECUTE_HANDLER;
}


extern "C" NTSTATUS NtReadFile_hook(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
)
{
    BOOLEAN should_intercept = FALSE;

    // Check if we should intercept BEFORE calling original
    if (is_chosen_target(PsGetCurrentProcess()) && FileHandle != NULL)
    {
        should_intercept = get_file_info(FileHandle);
        if (should_intercept && Length != 802268)
        {
            ang_debug("Intercepted NtReadFile for target process %u with unexpected length %lu\n",
                driver_state::get_instance().target_process_id, Length);
            should_intercept = FALSE;
        }
    }

    // Call original function
    auto status = o_NtReadFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key
    );

    if (NT_SUCCESS(status) && should_intercept)
    {
        if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
        {
            ang_debug("IRQL too high (%d) for buffer modification\n", KeGetCurrentIrql());
            return status;
        }

        __try
        {
            if (IoGetCurrentProcess() != PsGetCurrentProcess())
            {
                ang_debug("Process context mismatch\n");
                return status;
            }

            if ((ULONG_PTR)Buffer >= (ULONG_PTR)MmUserProbeAddress)
            {
                ProbeForWrite(Buffer, 802268, 1);
            }

            RtlCopyMemory(Buffer, rawData, 802268);
            ang_debug("File data replaced successfully\n");
        }
        __except (ExceptionFilter(GetExceptionInformation()))
        {
            ;
        }
    }

    return status;
}