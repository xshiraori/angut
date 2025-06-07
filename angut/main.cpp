#include <ntifs.h>
#include <memory.hpp>
#include <utils.hpp>
#include <callbacks.hpp>
#include <communication.hpp>
#include <memory_handler.hpp>
#include <callback_handler.hpp>

static const UNICODE_STRING g_DeviceName =
RTL_CONSTANT_STRING(L"\\Device\\angut");
static const UNICODE_STRING g_SymbolicLink =
RTL_CONSTANT_STRING(L"\\DosDevices\\angut");

extern "C" VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
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

    utils::logger::debug("received ioctl %x!\n", code);

    switch (code)
    {
    case IOCTL_READ_PROCESS_MEMORY:
    case IOCTL_WRITE_PROCESS_MEMORY:
    {
        if (inLen < sizeof(ioctl::handler::memory_copy_request))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Complete;
        }

        auto req = reinterpret_cast<ioctl::handler::memory_copy_request*>(Irp->AssociatedIrp.SystemBuffer);

        if (code == IOCTL_READ_PROCESS_MEMORY)
        {
            ioctl::handler::handle_memory_read_request(*req, status);
        }
        else
        {
            ioctl::handler::handle_memory_write_request(*req, status);
        }
        break;
    }
    case IOCTL_ENUMERATE_CALLBACKS:
    {
        if (outLen < sizeof(ioctl::handler::enumerate_callbacks_response)) 
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto req = reinterpret_cast<ioctl::handler::enumerate_callbacks_request*>(
            Irp->AssociatedIrp.SystemBuffer
            );

        ioctl::handler::handle_callback_enumerate_request(
            req,
            outLen,
            status,
            info
        );
        break;
    }
    case IOCTL_PATCH_CALLBACK:
    {
        if (outLen < sizeof(ioctl::handler::patch_callback_request)) 
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto req = reinterpret_cast<ioctl::handler::patch_callback_request*>(
            Irp->AssociatedIrp.SystemBuffer
            );

        ioctl::handler::handle_patch_callback_request(
            req,
            outLen,
            status,
            info
        );
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

    DriverObject->MajorFunction[IRP_MJ_CREATE] = MemDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MemDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MemDispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

