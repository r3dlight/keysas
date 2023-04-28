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

#include "keysasUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KfInstanceContextCleanup)
#pragma alloc_text(PAGE, KfInstanceQueryTeardown)
#pragma alloc_text(PAGE, KfInstanceSetup)
#pragma alloc_text(PAGE, KfInstanceTeardownComplete)
#pragma alloc_text(PAGE, KfInstanceTeardownStart)
#pragma alloc_text(PAGE, FindInstanceContext)
#pragma alloc_text(PAGE, KeysasScanInstanceInUserMode)
#endif

NTSTATUS
FindInstanceContext(
	_In_ PFLT_INSTANCE Instance,
	_Outptr_ PKEYSAS_INSTANCE_CTX* InstanceContext,
	_Out_opt_ PBOOLEAN ContextCreated
)
/*++

Routine Description:

	Find an existing instance context or create one if there is none

Arguments:

	Instance - Pointer to the instance

	InstanceContext - Pointer to the Instance context

	ContextCreated - Set to TRUE if the context has been created during the call

Return Value:

	The return value is the status of the operation.

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	PKEYSAS_INSTANCE_CTX instanceContext = NULL;
	PKEYSAS_INSTANCE_CTX oldInstanceContext = NULL;

	PAGED_CODE();

	// Initialize output paramters
	*InstanceContext = NULL;
	if (NULL != ContextCreated) {
		*ContextCreated = FALSE;
	}
	else {
		// ContextCreated must point to valid memory
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindInstanceContext: Invalid input\n"));
		return STATUS_UNSUCCESSFUL;
	}

	// Try to find an existing instance context
	status = FltGetInstanceContext(
		Instance,
		&instanceContext
	);

	// If the call fail because the context does not exist, create a new one
	if (!NT_SUCCESS(status)
		&& (STATUS_NOT_FOUND == status)) {

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindInstanceContext: Instance context not found\n"));
		status = FltAllocateContext(
			KeysasData.Filter,
			FLT_INSTANCE_CONTEXT,
			KEYSAS_INSTANCE_CTX_SIZE,
			PagedPool,
			&instanceContext
		);
		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindInstanceContext: FltAllocateContext failed with status: %0x8x\n",
				status));
			return status;
		}

		// Initialize the context
		// Set all the fields to 0 => Authorization = UNKNOWN
		RtlZeroMemory(instanceContext, KEYSAS_INSTANCE_CTX_SIZE);
		instanceContext->Resource = ExAllocatePoolZero(
			NonPagedPool,
			sizeof(ERESOURCE),
			KEYSAS_MEMORY_TAG
		);
		if (NULL == instanceContext->Resource) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindInstanceContext: ExAllocatePoolZero failed with status: %0x8x\n",
				status));
			FltReleaseContext(instanceContext);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		ExInitializeResourceLite(instanceContext->Resource);

		// Attach the context to the file
		status = FltSetInstanceContext(
			Instance,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			instanceContext,
			&oldInstanceContext
		);

		if (!NT_SUCCESS(status)) {
			FltReleaseContext(instanceContext);

			if (STATUS_FLT_CONTEXT_ALREADY_DEFINED != status) {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindInstanceContext: FltSetInstanceContext failed with status: %0x8x\n",
					status));
				return status;
			}

			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindInstanceContext: Instance context already defined\n"));
			// A context already exists
			instanceContext = oldInstanceContext;
			status = STATUS_SUCCESS;
		}
		else {
			// Successful creation of a new file context
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindInstanceContext: Created a new instance context\n"));
			*ContextCreated = TRUE;
		}
	}

	*InstanceContext = instanceContext;

	return status;
}

NTSTATUS
KeysasScanInstanceInUserMode(
	_In_ PUNICODE_STRING InstanceName,
	_In_ KEYSAS_FILTER_OPERATION Operation,
	_Out_ PBOOLEAN SafeToOpen
)
/*++
Routine Description:
	This routine is called to send a request up to user mode to scan a given
	instance and tell our caller whether it's safe to open it.
Arguments:
	FileName - Name of the file. It should be NORMALIZED thus the complete path is given
	Operation - Operation code for the user app
	SafeToOpen - Set to TRUE if the instance is valid
Return Value:
	The status of the operation, hopefully STATUS_SUCCESS.  The common failure
	status will probably be STATUS_INSUFFICIENT_RESOURCES.
--*/

{
	NTSTATUS status = STATUS_SUCCESS;
	PKEYSAS_DRIVER_REQUEST request = NULL;
	ULONG replyLength = 0;

	PAGED_CODE();

	// Set default authorization to true
	*SafeToOpen = TRUE;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanInstanceInUserMode: Entered\n"));

	if (NULL == KeysasData.ClientPort) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanInstanceInUserMode: Invalid client port\n"));
		return status;
	}

	if (InstanceName->Length > (KEYSAS_REQUEST_BUFFER_SIZE - 1)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanInstanceInUserMode: File name too long\n"));
	}

	// Allocate request buffer
	request = ExAllocatePoolZero(
		NonPagedPool,
		sizeof(KEYSAS_DRIVER_REQUEST),
		KEYSAS_MEMORY_TAG
	);

	if (NULL == request) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto end;
	}

	// Copy the name of the file in the request
	status = RtlStringCbCopyUnicodeString(request->Content, KEYSAS_REQUEST_BUFFER_SIZE * sizeof(WCHAR), InstanceName);
	if (STATUS_SUCCESS != status) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanInstanceInUserMode: Failed to convert UNICODE_STRING\n"));
		goto end;
	}
	request->Operation = Operation;

	replyLength = sizeof(*request);

	// Send request to userspace
	status = FltSendMessage(
		KeysasData.Filter,
		&KeysasData.ClientPort,
		request,
		sizeof(request->Content),
		request,
		&replyLength,
		NULL
	);

	if (STATUS_SUCCESS == status) {
		*SafeToOpen = ((PKEYSAS_REPLY)request)->Result;
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanInstanceInUserMode: Received result\n"));
	}
	else {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanInstanceInUserMode: Failed to send request to userspace\n"));
	}

end:
	if (NULL != request) {
		ExFreePoolWithTag(request, KEYSAS_MEMORY_TAG);
	}

	return status;
}

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
	UNREFERENCED_PARAMETER(VolumeDeviceType);

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
	BOOLEAN						instanceCreated = FALSE;
	wchar_t						nameBuffer[512] = { 0 };
	UNICODE_STRING				volumeName = { 0, sizeof(nameBuffer)-sizeof(wchar_t), nameBuffer};
	BOOLEAN						instanceValid = TRUE;

	// Print debug info on the call context
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Entered\n"));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Attached to (Volume = %p, Instance = %p, Device type = %08x\n",
		FltObjects->Volume,
		FltObjects->Instance,
		VolumeDeviceType));

	// Open the volume to get information on it
	status = FltOpenVolume(FltObjects->Instance, &FsVolumeHandle, &FsFileObject);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FltOpenVolume failed with status = %0x8x\n", status));
		goto end;
	}

	// Create a query and get the storage descriptor header
	SizeNeeded = max(sizeof(STORAGE_DESCRIPTOR_HEADER), sizeof(STORAGE_PROPERTY_QUERY));
	OutputBuffer = (PSTORAGE_PROPERTY_QUERY)ExAllocatePool2(POOL_FLAG_NON_PAGED, SizeNeeded, KEYSAS_MEMORY_TAG);
	if (NULL == OutputBuffer) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: ExAllocatePool2 failed\n"));
		goto end;
	}

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
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FltDeviceIoControlFile failed with status = %0x8x\n", status));
		goto end;
	}

	// Get the header size and update the query with the correct size
	OutputLength = HeaderDescriptor.Size;
	if (OutputLength < sizeof(STORAGE_DESCRIPTOR_HEADER)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Invalid output length\n"));
		goto end;
	}

	SizeRequired = max(OutputLength, sizeof(STORAGE_PROPERTY_QUERY));
	buffer = (PSTORAGE_PROPERTY_QUERY)ExAllocatePool2(POOL_FLAG_NON_PAGED, SizeRequired, KEYSAS_MEMORY_TAG);
	if (NULL == buffer) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: ExAllocatePool2 failed\n"));
		goto end;
	}

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
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FltDeviceIoControlFile failed with status = %0x8x\n", status));
		goto end;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Storage property size = %lu\n", RetLength));

	pStorageDesciptor = (PSTORAGE_ADAPTER_DESCRIPTOR)buffer;
	if (pStorageDesciptor->BusType == BusTypeUsb) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: USB descriptor found attach\n"));
		status = STATUS_SUCCESS;

		status = FindInstanceContext(
			FltObjects->Instance,
			&instanceContext,
			&instanceCreated
		);

		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FindInstanceContext failed with status = %0x8x\n", status));
			status = STATUS_FLT_DO_NOT_ATTACH;
			goto end;
		}

		// TODO: default set instance to ALLOW
		AcquireResourceWrite(instanceContext->Resource);

		status = FltGetVolumeName(FltObjects->Volume, &volumeName, NULL);

		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: FltGetVolumeName failed with status = %0x8x\n", status));
			status = STATUS_FLT_DO_NOT_ATTACH;
			goto end;
		}

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Volume name = %wZ\n", volumeName));

		status = KeysasScanInstanceInUserMode(
			&volumeName,
			SCAN_USB,
			&instanceValid
		);

		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: KeysasScanInstanceInUserMode failed with status = %0x8x\n", status));
			status = STATUS_FLT_DO_NOT_ATTACH;
			goto end;
		}

		instanceContext->Authorization = AUTH_ALLOW_WARNING;
		ReleaseResource(instanceContext->Resource);

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceSetup: Instance context attached\n"));
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
		if (NULL != instanceContext->Resource) {
			ReleaseResource(instanceContext->Resource);
		}
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

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceContextCleanup: Entered\n"));

	switch (ContextType) {
	case FLT_INSTANCE_CONTEXT:
		instanceContext = (PKEYSAS_INSTANCE_CTX)Context;
		if (instanceContext->Resource != NULL) {
			ExDeleteResourceLite(instanceContext->Resource);
			ExFreePoolWithTag(instanceContext->Resource, KEYSAS_MEMORY_TAG);
		}
		instanceContext->Authorization = AUTH_UNKNOWN;
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceContextCleanup: Cleaned instance context\n"));
		break;
	default:
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfInstanceContextCleanup: Unsupport context type\n"));
		break;
	}
}