/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	keysasInstance.c

Abstract:

	Contains the callback to handle transactions to the filter instance.

Environment:

	Kernel mode

--*/

#include "keysasInstance.h"

#include <fltKernel.h>
#include <ntddstor.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include <ntdef.h>

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

	NTSTATUS					status = STATUS_UNSUCCESSFUL;
	HANDLE						FsVolumeHandle = { 0 };
	PFILE_OBJECT				FsFileObject = NULL;
	STORAGE_PROPERTY_ID			PropertyId = StorageAdapterProperty;
	PSTORAGE_PROPERTY_QUERY		OutputBuffer = NULL;
	PSTORAGE_PROPERTY_QUERY		buffer = NULL;
	PSTORAGE_PROPERTY_QUERY		Query = NULL;
	PSTORAGE_PROPERTY_QUERY		pQuery = NULL;
	PSTORAGE_ADAPTER_DESCRIPTOR	pStorageDesciptor = NULL;
	STORAGE_DESCRIPTOR_HEADER	HeaderDescriptor = { 0 };
	ULONG						SizeNeeded, RetLength, OutputLength, SizeRequired;
	PKEYSAS_INSTANCE_CTX		instanceContext = NULL;

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
	OutputBuffer = (PSTORAGE_PROPERTY_QUERY)ExAllocatePool2(POOL_FLAG_NON_PAGED, SizeNeeded, KEYSAS_MEMORY_TAG);
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
	buffer = (PSTORAGE_PROPERTY_QUERY)ExAllocatePool2(POOL_FLAG_NON_PAGED, SizeRequired, KEYSAS_MEMORY_TAG);
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

		// Create a context for the instance
		status = FltAllocateContext(
			FltObjects->Filter,
			FLT_INSTANCE_CONTEXT,
			KEYSAS_INSTANCE_CTX_SIZE,
			NonPagedPool,
			&instanceContext
		);
		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FltAllocateContext failed with status = 0x%x\n", status));
			status = STATUS_FLT_DO_NOT_ATTACH;
			goto end;

		}

		instanceContext->Authorization = AUTH_UNKNOWN;
		instanceContext->Resource = NULL;

		status = FltSetInstanceContext(
			FltObjects->Instance,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			instanceContext,
			NULL
		);
		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FltSetInstanceContext failed with status = 0x%x\n", status));
			status = STATUS_FLT_DO_NOT_ATTACH;
			goto end;

		}
	}
	else {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Not a USB device do not attach\n"));
		status = STATUS_FLT_DO_NOT_ATTACH;
	}

end:
	if (OutputBuffer != NULL) {
		ExFreePoolWithTag(OutputBuffer, KEYSAS_MEMORY_TAG);
		OutputBuffer = NULL;
	}

	if (buffer != NULL) {
		ExFreePoolWithTag(buffer, KEYSAS_MEMORY_TAG);
		buffer = NULL;
	}

	if (FsVolumeHandle) {
		FltClose(FsVolumeHandle);
	}

	if (FsFileObject != NULL) {
		ObDereferenceObject(FsFileObject);
		FsFileObject = NULL;
	}

	if (instanceContext != NULL) {
		FltReleaseContext(instanceContext);
		instanceContext = NULL;
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

VOID
KfInstanceContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
)
/*++
Routine Description:
	This routine is called to cleanup the ressource allocated with the context
Arguments:
	Context - Pointer to the context
	ContextType - Type of context received
Return Value:
--*/
{
	PKEYSAS_INSTANCE_CTX instanceContext;

	PAGED_CODE();

	switch (ContextType) {
	case FLT_INSTANCE_CONTEXT:
		instanceContext = (PKEYSAS_INSTANCE_CTX)Context;
		if (instanceContext->Resource != NULL) {
			ExDeleteResourceLite(instanceContext->Resource);
			ExFreePoolWithTag(instanceContext->Resource, KEYSAS_MEMORY_TAG);
		}
		instanceContext->Authorization = AUTH_UNKNOWN;
		break;
	default:
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfContextCleanup: Unsupport context type\n"));
		break;
	}
}