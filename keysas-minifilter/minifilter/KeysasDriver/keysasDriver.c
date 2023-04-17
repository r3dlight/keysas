/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

    keysasDriver.c

Abstract:

    This filter intercept all operations on files stored on removable media and
    check if they have been validated by a Keysas station.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <ntddstor.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
KfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
KfInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
KfInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
KfUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
KfInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
KfPreCreateHandler(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID
KfOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
KfPostCreateHandler(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

BOOLEAN
KfDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, KfUnload)
#pragma alloc_text(PAGE, KfInstanceQueryTeardown)
#pragma alloc_text(PAGE, KfInstanceSetup)
#pragma alloc_text(PAGE, KfInstanceTeardownStart)
#pragma alloc_text(PAGE, KfInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    
    { IRP_MJ_CREATE,
      0,
      KfPreCreateHandler,
      KfPostCreateHandler },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    KfUnload,                           //  MiniFilterUnload

    KfInstanceSetup,                    //  InstanceSetup
    KfInstanceQueryTeardown,            //  InstanceQueryTeardown
    KfInstanceTeardownStart,            //  InstanceTeardownStart
    KfInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
KfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are alwasys created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    NTSTATUS                    status              = STATUS_UNSUCCESSFUL;
    HANDLE                      FsVolumeHandle      = {0};
    PFILE_OBJECT                FsFileObject        = NULL;
    STORAGE_PROPERTY_ID         PropertyId          = StorageAdapterProperty;
    PSTORAGE_PROPERTY_QUERY     OutputBuffer        = NULL;
    PSTORAGE_PROPERTY_QUERY     buffer              = NULL;
    PSTORAGE_PROPERTY_QUERY     Query               = NULL;
    PSTORAGE_PROPERTY_QUERY     pQuery              = NULL;
    PSTORAGE_ADAPTER_DESCRIPTOR pStorageDesciptor   = NULL;
    STORAGE_DESCRIPTOR_HEADER   HeaderDescriptor;
    ULONG                       SizeNeeded, RetLength, OutputLength, SizeRequired;

    // Print debug info on the call context
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Entered\n"));

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Attached to (Volume = %p, Instance = %p, Device type = %08x\n",
        FltObjects->Volume,
        FltObjects->Instance,
        VolumeDeviceType));

    // Open the volume to get information on it
    status = FltOpenVolume(FltObjects->Instance, &FsVolumeHandle, &FsFileObject);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FltOpenVolume failed with status = 0x%x\n", status));
        goto end;
    }

    // Create a query and get the storage descriptor header
    SizeNeeded = max(sizeof(STORAGE_DESCRIPTOR_HEADER), sizeof(STORAGE_PROPERTY_QUERY));
    OutputBuffer = (PSTORAGE_PROPERTY_QUERY)ExAllocatePool2(POOL_FLAG_NON_PAGED, SizeNeeded, 'VedR');
    ASSERT(OutputBuffer != NULL);

    RtlZeroMemory(OutputBuffer, SizeNeeded);

    Query = (PSTORAGE_PROPERTY_QUERY)OutputBuffer;
    Query->PropertyId = PropertyId;
    Query->QueryType = PropertyStandardQuery;

    status = FltDeviceIoControlFile(
        FltObjects->Instance,
        FsFileObject,
        IOCTL_STORAGE_QUERY_PROPERTY,
        Query,
        sizeof(STORAGE_PROPERTY_QUERY),
        &HeaderDescriptor,
        sizeof(STORAGE_DESCRIPTOR_HEADER),
        &RetLength);

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FltDeviceIoControlFile failed with status = 0x%x\n", status));
        goto end;
    }

    // Get the header size and update the query with the correct size
    OutputLength = HeaderDescriptor.Size;
    ASSERT(OutputLength >= sizeof(STORAGE_DESCRIPTOR_HEADER));

    SizeRequired = max(OutputLength, sizeof(STORAGE_PROPERTY_QUERY));
    buffer = (PSTORAGE_PROPERTY_QUERY)ExAllocatePool2(POOL_FLAG_NON_PAGED, SizeRequired, 'VedR');
    ASSERT(buffer != NULL);

    RtlZeroMemory(buffer, SizeRequired);
    pQuery = (PSTORAGE_PROPERTY_QUERY)buffer;
    pQuery->PropertyId = PropertyId;
    pQuery->QueryType = PropertyStandardQuery;

    status = FltDeviceIoControlFile(
        FltObjects->Instance,
        FsFileObject,
        IOCTL_STORAGE_QUERY_PROPERTY,
        pQuery,
        sizeof(STORAGE_PROPERTY_QUERY),
        buffer,
        OutputLength,
        &RetLength
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FltDeviceIoControlFile failed with status = 0x%x\n", status));
        goto end;
    }

    pStorageDesciptor = (PSTORAGE_ADAPTER_DESCRIPTOR)buffer;
    if (pStorageDesciptor->BusType == BusTypeUsb) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: USB descriptor found attach\n"));
        status = STATUS_SUCCESS;
    }
    else {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Not a USB device do not attach\n"));
        status = STATUS_FLT_DO_NOT_ATTACH;
    }

end:
    if (OutputBuffer != NULL) {
        ExFreePoolWithTag(OutputBuffer, 'VedR');
        OutputBuffer = NULL;
    }

    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, 'VedR');
        buffer = NULL;
    }

    if (FsVolumeHandle) {
        FltClose(FsVolumeHandle);
    }

    if (FsFileObject != NULL) {
        ObDereferenceObject(FsFileObject);
        FsFileObject = NULL;
    }

    return status;
}


NTSTATUS
KfInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}


VOID
KfInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is been deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceTeardownStart: Entered\n"));
}


VOID
KfInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is been deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceTeardownComplete: Entered\n"));
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas: DriverEntry\n"));

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering(gFilterHandle);

        if (!NT_SUCCESS(status)) {

            FltUnregisterFilter(gFilterHandle);
        }
    }

    return status;
}

NTSTATUS
KfUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unloaded indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns the final status of this operation.

--*/
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfUnload: Entered\n"));

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
KfPreCreateHandler(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreCreateHandler: Major:%08x, Minor:%08x\n",
        Data->Iopb->MajorFunction,
        Data->Iopb->MinorFunction));

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
KfPostCreateHandler(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:
    
    Post create callback.
    File scanning must be done after the create has gone to the file system in order to read the file.

    Test if the file is a Keysas report. If not send check its validity before allowing to open it.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Entered\n"));

    // If the create is failing, don't bother with it
    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        (STATUS_REPARSE == Data->IoStatus.Status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Failing create call\n"));
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Check if the file is of interest
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: FltGetFileNameInformation failed with status: 0x%x\n",
            status));
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FltParseFileNameInformation(nameInfo);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: File extension is: %wZ\n",
        nameInfo->Extension));

    FltReleaseFileNameInformation(nameInfo);

    return FLT_POSTOP_FINISHED_PROCESSING;
}
