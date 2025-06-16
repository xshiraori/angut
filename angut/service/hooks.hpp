#pragma once
#include <ntifs.h>
#include "nt_internals.hpp"

extern decltype(NtQuerySystemInformation)* g_oldFunction;

extern "C" NTSTATUS NtQuerySystemInformation_hook(
    ULONG SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);