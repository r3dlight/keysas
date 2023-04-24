/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	keysasFile.c

Abstract:

	Contains the callback to handle transactions on file access

Environment:

	Kernel mode

--*/

#include "keysasFile.h"

#include <fltKernel.h>
#include <ntddstor.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include <ntdef.h>

#include "keysasDriver.h"
#include "keysasCommunication.h"
#include "keysasUtils.h"

VOID
KfFileContextCleanup(
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
	PKEYSAS_FILE_CTX fileContext;

	PAGED_CODE();

	switch (ContextType) {
	case FLT_FILE_CONTEXT:
		fileContext = (PKEYSAS_FILE_CTX)Context;
		if (fileContext->Resource != NULL) {
			ExDeleteResourceLite(fileContext->Resource);
			ExFreePoolWithTag(fileContext->Resource, KEYSAS_MEMORY_TAG);
		}
		fileContext->Authorization = AUTH_UNKNOWN;
		break;
	default:
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfContextCleanup: Unsupport context type\n"));
		break;
	}
}

NTSTATUS
FindFileContext(
	_In_ PFLT_CALLBACK_DATA Data,
	_Outptr_ PKEYSAS_FILE_CTX *FileContext,
	_Out_opt_ PBOOLEAN ContextCreated
)
/*++

Routine Description:

	Find an existing file context or create one if there is none

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FileContext - Pointer to the File context

	ContextCreated - Set to TRUE if the context has been created during the call

Return Value:

	The return value is the status of the operation.

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	PKEYSAS_FILE_CTX fileContext = NULL;
	PKEYSAS_FILE_CTX oldFileContext = NULL;

	PAGED_CODE();

	// Initialize output paramters
	*FileContext = NULL;
	if (NULL != ContextCreated) {
		*ContextCreated = FALSE;
	}
	else {
		// ContextCreated must point to valid memory
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: Invalid input\n"));
		return STATUS_UNSUCCESSFUL;
	}

	// Try to find an existing file context
	status = FltGetFileContext(
		Data->Iopb->TargetInstance,
		Data->Iopb->TargetFileObject,
		&fileContext
	);

	// If the call fail because the context does not exist, create a new one
	if (!NT_SUCCESS(status)
		&& (STATUS_NOT_FOUND == status)) {

		status = FltAllocateContext(
			KeysasData.Filter,
			FLT_FILE_CONTEXT,
			KEYSAS_FILE_CTX_SIZE,
			PagedPool,
			&fileContext
		);
		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: FltAllocateContext failed with status: 0x%x\n",
				status));
			return status;
		}

		// Initialize the context
		// Set all the fields to 0 => Authorization = UNKNOWN
		RtlZeroMemory(fileContext, KEYSAS_FILE_CTX_SIZE);
		fileContext->Resource = ExAllocatePoolZero(
			NonPagedPool,
			sizeof(ERESOURCE),
			KEYSAS_MEMORY_TAG
		);
		if (NULL == fileContext->Resource) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: ExAllocatePoolZero failed with status: 0x%x\n",
				status));
			FltReleaseContext(fileContext);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		ExInitializeResourceLite(fileContext->Resource);

		// Attach the context to the file
		status = FltSetFileContext(
			Data->Iopb->TargetInstance,
			Data->Iopb->TargetFileObject,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			fileContext,
			&oldFileContext
		);

		if (!NT_SUCCESS(status)) {
			FltReleaseContext(fileContext);

			if (STATUS_FLT_CONTEXT_ALREADY_DEFINED != status) {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: FltSetFileContext failed with status: 0x%x\n",
					status));
				FltReleaseContext(fileContext);
				return status;
			}

			// A context already exists
			fileContext = oldFileContext;
			status = STATUS_SUCCESS;
		}
		else {
			// Successful creation of a new file context
			*ContextCreated = TRUE;
		}
	}

	*FileContext = fileContext;

	return status;
}

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
	NTSTATUS status = STATUS_SUCCESS;
	NTSTATUS result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	// Check if the file is of interest
	status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo
	);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreCreateHandler: FltGetFileNameInformation failed with status: 0x%x\n",
			status));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	FltParseFileNameInformation(nameInfo);

	if (0 == nameInfo->FinalComponent.Length) {
		// Not a file but a directory
		// No need to intercept POST operation
		result = FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FltReleaseFileNameInformation(nameInfo);

	return result;
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
	NTSTATUS status = STATUS_SUCCESS;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	BOOLEAN safeToOpen = TRUE;
	PKEYSAS_FILE_CTX fileContext = NULL;
	BOOLEAN contextCreated = FALSE;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

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

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: File Name:%wZ, Extension: %wZ, Volume: %wZ\n",
		nameInfo->Name,
		nameInfo->Extension,
		nameInfo->Volume));

	FltReleaseFileNameInformation(nameInfo);

	// Find or create File context
	status = FindFileContext(Data, &fileContext, &contextCreated);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: FindFileContext failed with status: 0x%x\n",
			status));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	// Acquire lock on File context
	// By default acquire in shared mode only to read the authorization state
	// If the authorization state is unknown then try to acquire the lock in write mode to scan the file
	AcquireResourceRead(fileContext->Resource);

	if (AUTH_UNKNOWN == fileContext->Authorization) {
		// The authorization status is not known for this file
		// Get a write lock
		ReleaseResource(fileContext->Resource);
		AcquireResourceWrite(fileContext->Resource);
		// Test the authorization again as it can have been preempted
		if (AUTH_UNKNOWN == fileContext->Authorization) {
			fileContext->Authorization = AUTH_PENDING;
			// Send the file to further analysis in user space
			(VOID)KeysasScanFileInUserMode(
				&nameInfo->Name,
				&safeToOpen
			);

			// TODO: by default allow all files
			fileContext->Authorization = AUTH_ALLOW_READ;
		}
	}

	switch (fileContext->Authorization) {
	case AUTH_BLOCK:
		// Block the transaction
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		break;
	case AUTH_PENDING:
	case AUTH_UNKNOWN:
		// These states should not happen
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Error inconsistent file authorization\n"));
	default:
		// Unless the file is explicitely blocked do nothing and allow the transaction
		break;
	}

	ReleaseResource(fileContext->Resource);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS
KeysasScanFileInUserMode(
	_In_ PUNICODE_STRING FileName,
	_Out_ PBOOLEAN SafeToOpen
)
/*++
Routine Description:
	This routine is called to send a request up to user mode to scan a given
	file and tell our caller whether it's safe to open this file.
	Note that if the scan fails, we set SafeToOpen to TRUE.  The scan may fail
	because the service hasn't started, or perhaps because this create/cleanup
	is for a directory, and there's no data to read & scan.
	If we failed creates when the service isn't running, there'd be a
	bootstrapping problem -- how would we ever load the .exe for the service?
Arguments:
	FileName - Name of the file. It should be NORMALIZED thus the complete path is given
	SafeToOpen - Set to FALSE if the file is scanned successfully and it contains
				 foul language.
Return Value:
	The status of the operation, hopefully STATUS_SUCCESS.  The common failure
	status will probably be STATUS_INSUFFICIENT_RESOURCES.
--*/

{
	NTSTATUS status = STATUS_SUCCESS;
	PKEYSAS_DRIVER_REQUEST request = NULL;
	ULONG replyLength = 0;

	// Set default authorization to true
	*SafeToOpen = TRUE;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: Entered\n"));

	if (NULL == KeysasData.ClientPort) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: Invalid client port\n"));
		return status;
	}

	if (FileName->Length > (KEYSAS_REQUEST_BUFFER_SIZE - 1)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: File name too long\n"));
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
	status = RtlStringCbCopyUnicodeString(request->Content, KEYSAS_REQUEST_BUFFER_SIZE * sizeof(WCHAR), FileName);
	if (STATUS_SUCCESS != status) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: Failed to convert UNICODE_STRING\n"));
		goto end;
	}

	replyLength = sizeof(request);

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
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: Result: %p\n", SafeToOpen));
	}
	else {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: Failed to send request to userspace\n"));
	}

end:
	if (NULL != request) {
		ExFreePoolWithTag(request, KEYSAS_MEMORY_TAG);
	}

	return status;
}