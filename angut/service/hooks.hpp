#pragma once
#include <ntifs.h>
#include "nt_internals.hpp"

extern decltype(NtQuerySystemInformation)* o_NtQuerySystemInformation;
extern decltype(NtOpenProcess)* o_NtOpenProcess;
extern decltype(NtReadFile)* o_NtReadFile;

extern "C" NTSTATUS NtQuerySystemInformation_hook(
    ULONG SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

extern "C" NTSTATUS NtOpenProcess_hook(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

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
);