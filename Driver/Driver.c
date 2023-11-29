#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>

#define IO_GET_ID_REQUEST  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6210, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6211, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6212, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_GET_MODULE_REQUEST  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6213, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

ULONG processId, ClientAddress;
PDEVICE_OBJECT pDeviceObject;

typedef struct _KERNEL_READ_REQUEST {
    ULONG ProcessId; // target process id
    ULONG Address;   // address of memory to start reading from
    PVOID pBuff;     // return value
    ULONG Size;      // size of memory to read
} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
    ULONG ProcessId; // target process id
    ULONG Address;   // address of memory to start reading from
    PVOID pBuff;     // return value
    ULONG Size;      // size of memory to read
} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

NTSTATUS KernelReadVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
    SIZE_T Bytes;
    return MmCopyVirtualMemory(SourceProcess, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &Bytes);
}

NTSTATUS KernelWriteVirtualMemory(PEPROCESS TargetProcess, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
    SIZE_T Bytes;
    return MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Bytes);
}

NTSTATUS ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    if (wcsstr(FullImageName->Buffer, L"\\Genshin Impact\\Genshin Impact game\\GenshinImpact.exe")) {
        ClientAddress = (ULONG)ImageInfo->ImageBase;
        processId = (ULONG)HandleToUlong(ProcessId);
    }

    return STATUS_SUCCESS;
}


NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG ByteIo = 0;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    if (ControlCode == IO_READ_REQUEST) {
        PKERNEL_READ_REQUEST ReadInput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        PEPROCESS Process;

        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ReadInput->ProcessId, &Process))) {
            KernelReadVirtualMemory(Process, (PVOID)ReadInput->Address, ReadInput->pBuff, ReadInput->Size);
        }

        Status = STATUS_SUCCESS;
        ByteIo = sizeof(KERNEL_READ_REQUEST);
    }
    else if (ControlCode == IO_WRITE_REQUEST) {
        PKERNEL_WRITE_REQUEST WriteInput = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        PEPROCESS Process;

        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)WriteInput->ProcessId, &Process))) {
            KernelWriteVirtualMemory(Process, WriteInput->pBuff, (PVOID)WriteInput->Address, WriteInput->Size);
        }

        Status = STATUS_SUCCESS;
        ByteIo = sizeof(KERNEL_WRITE_REQUEST);
    }
    else if (ControlCode == IO_GET_ID_REQUEST) {
        PULONG OutPut = (PULONG)Irp->AssociatedIrp.SystemBuffer;
        *OutPut = processId;

        Status = STATUS_SUCCESS;
        ByteIo = sizeof(*OutPut);
    }
    else if (ControlCode == IO_GET_MODULE_REQUEST) {
        PULONG OutPut = (PULONG)Irp->AssociatedIrp.SystemBuffer;
        *OutPut = ClientAddress;

        Status = STATUS_SUCCESS;
        ByteIo = sizeof(*OutPut);
    }
    else {
        Status = STATUS_INVALID_PARAMETER;
        ByteIo = 0;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = ByteIo;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD MyEvtDeviceAdd;

EXTERN_C_END

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING  RegistryPath
)
{
    NTSTATUS status;

    KdPrint(("DriverEntry\n"));

    WDF_DRIVER_CONFIG config;

    WDF_DRIVER_CONFIG_INIT(&config, MyEvtDeviceAdd);

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             WDF_NO_OBJECT_ATTRIBUTES,
                             &config,
                             WDF_NO_HANDLE);

    return status;
}

NTSTATUS
MyEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    UNREFERENCED_PARAMETER(Driver);

    NTSTATUS status;

    WDFDEVICE hDevice;

    PAGED_CODE();

    KdPrint(("MyEvtDeviceAdd: Driver initialization started\n"));

    status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice);

    return status;
}