#include <ntifs.h>
#include <memory.hpp>
#include <utils.hpp>
#include <callbacks.hpp>
#include <communication.hpp>
#include <memory_handler.hpp>
#include <callback_handler.hpp>
#include <process_handler.hpp>
#include <ssdt.hpp>
#include <state.hpp>
#include <hooks.hpp>
#include <settings_handler.hpp>

static const UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\angut");
static const UNICODE_STRING g_SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\angut");

#define HANDLE_IOCTL(request_type, req, outLen, status, info) \
    if (outLen < sizeof(ioctl::handler::request_type)) { \
        status = STATUS_BUFFER_TOO_SMALL; \
        break; \
    } \
    auto req = reinterpret_cast<ioctl::handler::request_type*>(Irp->AssociatedIrp.SystemBuffer); \
    ioctl::handler::handle_##request_type(req, outLen, status, info); \

extern "C" VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    memory::ssdt::cleanup();
    UNICODE_STRING symLink = static_cast<UNICODE_STRING>(g_SymbolicLink);
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C"
NTSTATUS
MemDispatchCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS
MemDispatchDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION  stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG               code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS            status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR           info = 0;

    ang_debug("Received IOCTL: %x!\n", code);

    switch (code)
    {
        case IOCTL_READ_PROCESS_MEMORY:
        {
		    HANDLE_IOCTL(memory_read_request, req, outLen, status, info);
            break;
        }
        case IOCTL_WRITE_PROCESS_MEMORY:
        {
            HANDLE_IOCTL(memory_write_request, req, outLen, status, info);
            break;
        }
        case IOCTL_ENUMERATE_CALLBACKS:
        {
            HANDLE_IOCTL(enumerate_callbacks_request, req, outLen, status, info);
            break;
        }
        case IOCTL_PATCH_CALLBACK:
        {
            HANDLE_IOCTL(patch_callback_request, req, outLen, status, info);
            break;
        }
	    case IOCTL_DELETE_CALLBACK_PATCH:
	    {
            HANDLE_IOCTL(callback_delete_request, req, outLen, status, info);
            break;
	    }
        case IOCTL_CREATE_MANUAL_HANDLE:
        {
            HANDLE_IOCTL(create_user_handle_request, req, outLen, status, info);
            break;
        }
	    case IOCTL_GET_PROCESS_INFO:
	    {
		    HANDLE_IOCTL(get_process_info_request, req, outLen, status, info);
            break;
	    }
        case IOCTL_SELECT_TARGET_PROCESS:
        {
			HANDLE_IOCTL(select_target_process_request, req, outLen, status, info);
			break;
        }
        case IOCTL_SET_DRIVER_SETTINGS:
		{
			HANDLE_IOCTL(set_driver_settings_request, req, outLen, status, info);
			break;
		}

        default:
        {
            status = STATUS_INVALID_DEVICE_REQUEST;
        }
    }
Complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info; 
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


extern "C"
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS        status;
    PDEVICE_OBJECT  deviceObject = nullptr;

    status = IoCreateDevice(
        DriverObject,
        0, 
        const_cast<UNICODE_STRING*>(&g_DeviceName),
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) 
    {
        return status;
    }

    status = IoCreateSymbolicLink(
        const_cast<UNICODE_STRING*>(&g_SymbolicLink),
        const_cast<UNICODE_STRING*>(&g_DeviceName)
    );

    if (!NT_SUCCESS(status)) 
    {
        IoDeleteDevice(deviceObject);
        return status;
    }

	status = memory::initialize_constants();

    if (!NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(const_cast<UNICODE_STRING*>(&g_SymbolicLink));
        IoDeleteDevice(deviceObject);
        return status;
    }

    o_NtReadFile = memory::ssdt::get_function_by_entry<decltype(NtReadFile_hook)>(memory::CONSTANTS::WIN10::NtReadFile_Index);
    if (!o_NtReadFile)
    {
        ang_debug("Failed to get original NtReadFile function!\n");
        IoDeleteSymbolicLink(const_cast<UNICODE_STRING*>(&g_SymbolicLink));
        IoDeleteDevice(deviceObject);
        return STATUS_NOT_FOUND;
    }

    ang_debug("Original NtReadFile at: %p\n", o_NtReadFile);

    // Hook the function
    if (!memory::ssdt::hook_single_entry(memory::CONSTANTS::WIN10::NtReadFile_Index, NtReadFile_hook, o_NtReadFile))
    {
        ang_debug("Failed to hook NtReadFile!\n");
        IoDeleteSymbolicLink(const_cast<UNICODE_STRING*>(&g_SymbolicLink));
        IoDeleteDevice(deviceObject);
        return STATUS_UNSUCCESSFUL;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = MemDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MemDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MemDispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

