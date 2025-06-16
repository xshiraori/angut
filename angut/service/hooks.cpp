#include <hooks.hpp>
#include <state.hpp>
#include <utils.hpp>
#include <memory.hpp>

decltype(NtQuerySystemInformation)* g_oldFunction = nullptr;

extern "C" NTSTATUS NtQuerySystemInformation_hook(
    ULONG SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
)
{
    NTSTATUS status = g_oldFunction(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

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
