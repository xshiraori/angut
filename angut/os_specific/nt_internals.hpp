#pragma once
#include <ntifs.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

extern "C" NTSTATUS ZwQuerySystemInformation(
      ULONG SystemInformationClass,
      PVOID                    SystemInformation,
      ULONG                    SystemInformationLength,
      PULONG                   ReturnLength
);

extern "C" NTSTATUS
MmCopyVirtualMemory(
    IN PEPROCESS FromProcess,
    IN CONST VOID* FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
);

typedef struct _REGISTRY_CALLBACK_ITEM
{
    LIST_ENTRY Item;
    DWORD64 Unknown1[2];
    DWORD64 Context;
    DWORD64 Function;
    UNICODE_STRING Altitude;
    DWORD64 Unknown2[2];
} REGISTRY_CALLBACK_ITEM, * PREGISTRY_CALLBACK_ITEM;

typedef struct _CALLBACK_OBJECT
{
    ULONG Signature;
    KSPIN_LOCK Lock;
    LIST_ENTRY RegisteredCallbacks;
    BOOLEAN AllowMultipleCallbacks;
    UCHAR reserved[3];
} CALLBACK_OBJECT, * PCALLBACK_OBJECT;

typedef struct _CALLBACK_REGISTRATION
{
    LIST_ENTRY Link;
    PCALLBACK_OBJECT CallbackObject;
    PCALLBACK_FUNCTION CallbackFunction;
    PVOID CallbackContext;
    ULONG Busy;
    BOOLEAN UnregisterWaiting;
} CALLBACK_REGISTRATION, * PCALLBACK_REGISTRATION;

typedef VOID(*PCALLBACK_FUNCTION)(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
    );

typedef struct _OBJECT_TYPE_2
{
    LIST_ENTRY      TypeList;
    UNICODE_STRING	Name;
    void* DefaultObject;
    char			Index;
    unsigned int	TotalNumberOfObjects;
    unsigned int	TotalNumberOfHandles;
    unsigned int	HighWaterNumberOfObjects;
    unsigned int	HighWaterNumberOfHandles;
    char			TypeInfo[0x78];
    __int64			TypeLock;
    unsigned int	Key;
    LIST_ENTRY		CallbackList;
}OBJECT_TYPE_2, * POBJECT_TYPE_2;

typedef struct _OB_CALLBACK_INFO
{
    char 					Version;
    unsigned __int16 		NumberOfEntries;
    __int64 				RegistrationContext;
    UNICODE_STRING 			Altitude;
} OB_CALLBACK_INFO, * POB_CALLBACK_INFO;

typedef struct _OB_CALLBACK_ENTRY
{
    LIST_ENTRY					ListEntry;
    OB_OPERATION				Operations;
    ULONG32 Enabled;
    OB_CALLBACK_INFO* CallbackInfo;
    OBJECT_TYPE_2* ObjectType;
    POB_PRE_OPERATION_CALLBACK	PreOperation;
    POB_POST_OPERATION_CALLBACK	PostOperation;
    KSPIN_LOCK 					PushLock;
} OB_CALLBACK_ENTRY, * POB_CALLBACK_ENTRY;

typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF RundownProtect;
    PEX_CALLBACK_FUNCTION Function;
    PVOID Context;
} EX_CALLBACK_ROUTINE_BLOCK, * PEX_CALLBACK_ROUTINE_BLOCK;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;