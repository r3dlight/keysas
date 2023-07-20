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
#include "keysasInstance.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KfFileContextCleanup)
//#pragma alloc_text(PAGE, FindFileContext)
#pragma alloc_text(PAGE, KfPostCreateHandler)
#pragma alloc_text(PAGE, KfPreCreateHandler)
#pragma alloc_text(PAGE, KeysasScanFileInUserMode)
#endif

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
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfFileContextCleanup: Entered\n"));

	switch (ContextType) {
	case FLT_FILE_CONTEXT:
		fileContext = (PKEYSAS_FILE_CTX)Context;
		if (NULL != fileContext->FileID) {
			ExFreePoolWithTag(fileContext->FileID, KEYSAS_MEMORY_TAG);
		}
		if (NULL != fileContext->Resource) {
			ExDeleteResourceLite(fileContext->Resource);
			ExFreePoolWithTag(fileContext->Resource, KEYSAS_MEMORY_TAG);
		}
		fileContext->Authorization = AUTH_UNKNOWN;
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfFileContextCleanup: Cleaned context\n"));
		break;
	default:
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfFileContextCleanup: Unsupport context type\n"));
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

	//PAGED_CODE();

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

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: File context not found\n"));
		status = FltAllocateContext(
			KeysasData.Filter,
			FLT_FILE_CONTEXT,
			KEYSAS_FILE_CTX_SIZE,
			PagedPool,
			&fileContext
		);
		if (!NT_SUCCESS(status)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: FltAllocateContext failed with status: %0x8x\n",
				status));
			return status;
		}

		// Initialize the context
		// Set all the fields to 0 => Authorization = UNKNOWN
		RtlZeroMemory(fileContext, KEYSAS_FILE_CTX_SIZE);
		// Initialize the lock
		fileContext->Resource = ExAllocatePoolZero(
			NonPagedPool,
			sizeof(ERESOURCE),
			KEYSAS_MEMORY_TAG
		);
		if (NULL == fileContext->Resource) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: ExAllocatePoolZero failed with status: %0x8x\n",
				status));
			FltReleaseContext(fileContext);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		ExInitializeResourceLite(fileContext->Resource);
		fileContext->FileID = NULL;

		// Initialize and place the context in the list
		ExInterlockedInsertHeadList(
			&KeysasData.FileCtxListHead,
			&fileContext->FileCtxList,
			&KeysasData.FileCtxListLock);

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
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: FltSetFileContext failed with status: %0x8x\n",
					status));
				return status;
			}

			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: File context already defined\n"));
			// A context already exists
			fileContext = oldFileContext;
			status = STATUS_SUCCESS;
		}
		else {
			// Successful creation of a new file context
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!FindFileContext: Created a new file context\n"));
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
	PKEYSAS_INSTANCE_CTX instanceContext = NULL;
	BOOLEAN isDirectory = FALSE;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext = NULL);

	PAGED_CODE();

	// Allow call from our userspace application
	if (IoThreadToProcess(Data->Thread) == KeysasData.UserProcess) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Don't filter call to directories or volumes
	status = FltIsDirectory(Data->Iopb->TargetFileObject, FltObjects->Instance, &isDirectory);

	if (((Data->Iopb->TargetFileObject->FileName.Length == 0) && (Data->Iopb->TargetFileObject->RelatedFileObject == NULL)) ||
		isDirectory)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Get the instance context
	// If the instance is blocked, reject all calls
	status = FltGetInstanceContext(
		Data->Iopb->TargetInstance,
		&instanceContext
	);
	if (!NT_SUCCESS(status)) {
		// There should always be a context for an instance to which the filter is attached
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreCreateHandler: FltGetInstanceContext failed with status: %0x8x\n",
			status));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Get a read lock on the instance context
	if (!AcquireResourceRead(instanceContext->Resource)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Failed to acquire ressource in read mode\n"));
		FltReleaseContext(instanceContext);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Apply authorization state to the call
	switch (instanceContext->Authorization)
	{
	case AUTH_BLOCK:
		// Block all calls
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		FltSetCallbackDataDirty(Data);
		result = FLT_PREOP_COMPLETE;
		break;
	case AUTH_ALLOW_ALL:
		// Allow all call without verification
		result = FLT_PREOP_SUCCESS_NO_CALLBACK;
		break;
	case AUTH_UNKNOWN:
	case AUTH_PENDING:
		// These two states should not happen
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreCreateHandler: Invalid instance authorization state\n"));
	default:
		result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		break;
	}

	// Release resources
	ReleaseResource(instanceContext->Resource);
	FltReleaseContext(instanceContext);

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
	PKEYSAS_FILE_CTX fileContext = NULL;
	BOOLEAN contextCreated = FALSE;
	KEYSAS_FILTER_OPERATION operation = SCAN_FILE;
	PKEYSAS_INSTANCE_CTX instanceContext = NULL;
	POBJECT_NAME_INFORMATION msFileName = NULL;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	// If the create is failing, don't bother with it
	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(STATUS_REPARSE == Data->IoStatus.Status)) {
		status = FLT_POSTOP_FINISHED_PROCESSING;
		goto cleanup;
	}

	// Check if the file is of interest
	status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo
	);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: FltGetFileNameInformation failed with status: %0x8x\n",
			status));
		status = FLT_POSTOP_FINISHED_PROCESSING;
		goto cleanup;
	}

	FltParseFileNameInformation(nameInfo);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: File Name:%wZ, Extension: %wZ, Volume: %wZ\n",
		nameInfo->Name,
		nameInfo->Extension,
		nameInfo->Volume));

	// Find or create File context
	status = FindFileContext(Data, &fileContext, &contextCreated);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: FindFileContext failed with status: %0x8x\n",
			status));
		status = FLT_POSTOP_FINISHED_PROCESSING;
		goto cleanup;
	}
	// Acquire lock on File context
	// By default acquire in shared mode only to read the authorization state
	// If the authorization state is unknown then try to acquire the lock in write mode to scan the file
	if (!AcquireResourceRead(fileContext->Resource)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Failed to acquire ressource in read mode\n"));
		status = FLT_POSTOP_FINISHED_PROCESSING;
		goto cleanup;
	}

	if (AUTH_UNKNOWN == fileContext->Authorization) {
		// The authorization status is not known for this file
		// Get a write lock
		ReleaseResource(fileContext->Resource);
		if (!AcquireResourceWrite(fileContext->Resource)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Failed to acquire ressource in write mode\n"));
			status = FLT_POSTOP_FINISHED_PROCESSING;
			goto cleanup;
		}
		// Test the authorization again as it can have been preempted
		if (AUTH_UNKNOWN == fileContext->Authorization) {
			// Resume file context initialization
			fileContext->Authorization = AUTH_PENDING;

			IoQueryFileDosDeviceName(FltObjects->FileObject, &msFileName);

			// Compute hash of file name to store it in the file context
			if (STATUS_SUCCESS != KeysasGetFileNameHash(&msFileName->Name, &(fileContext->FileID))) {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Failed to compute file name hash\n"));
				status = FLT_POSTOP_FINISHED_PROCESSING;
				goto cleanup;
			}

			// Try to acquire the instance context as the file authorization will depend on the instance status
			status = FindInstanceContext(
				Data->Iopb->TargetInstance,
				&instanceContext,
				&contextCreated
			);
			if (!NT_SUCCESS(status)) {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: FindInstanceContext failed with status: %0x8x\n",
					status));
				status = FLT_POSTOP_FINISHED_PROCESSING;
				ReleaseResource(fileContext->Resource);
				goto cleanup;
			}

			// Get read access to the instance state
			if (!AcquireResourceRead(instanceContext->Resource)) {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Failed to acquire ressource in read mode\n"));
			}

			// Set the scan operation depending on the instance status
			operation = SCAN_FILE;
			switch (instanceContext->Authorization) {
			case AUTH_BLOCK:
				// Set the file to block mode
				ReleaseResource(instanceContext->Resource);
				fileContext->Authorization = AUTH_BLOCK;
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Instance blocked, File authorization BLOCK\n"));
				break;
			case AUTH_ALLOW_WARNING:
				// In this case, ask for the user authorization
				operation = USER_ALLOW_FILE;
			case AUTH_ALLOW_READ:
				// Ask the userspace to scan the file
				ReleaseResource(instanceContext->Resource);
				// Send the file to further analysis in user space
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Send request to userspace\n"));
				(VOID)KeysasScanFileInUserMode(
					&msFileName->Name,
					fileContext->FileID,
					operation,
					&fileContext->Authorization
				);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Received authorization status from userspace: %0x\n",
					fileContext->Authorization));
				break;
			case AUTH_ALLOW_ALL:
				// Set the file to allow mode
				ReleaseResource(instanceContext->Resource);
				fileContext->Authorization = AUTH_ALLOW_READ;
				break;
			default:
				// Should not happen, log and set file to blocking
				ReleaseResource(instanceContext->Resource);
				fileContext->Authorization = AUTH_BLOCK;
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Incoherent instance state, File authorization BLOCK\n"));
				break;
			}
		}
	}

	switch (fileContext->Authorization) {
	case AUTH_BLOCK:
		// Block the transaction
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		FltSetCallbackDataDirty(Data);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: File blocked\n"));
		break;
	case AUTH_PENDING:
	case AUTH_UNKNOWN:
		// These states should not happen
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPostCreateHandler: Error inconsistent file authorization\n"));
	default:
		// Unless the file is explicitely blocked do nothing and allow the transaction
		break;
	}

	status = FLT_POSTOP_FINISHED_PROCESSING;

cleanup:
	if (NULL != nameInfo) {
		FltReleaseFileNameInformation(nameInfo);
	}

	if (NULL != fileContext) {
		if (NULL != fileContext->Resource) {
			ReleaseResource(fileContext->Resource);
		}
		FltReleaseContext(fileContext);
	}

	if (NULL != instanceContext) {
		if (NULL != instanceContext->Resource) {
			ReleaseResource(instanceContext->Resource);
		}
		FltReleaseContext(instanceContext);
	}

	if (NULL != msFileName) {
		ExFreePool(msFileName);
	}

	return status;
}

FLT_PREOP_CALLBACK_STATUS
KfPreWriteHandler(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/***
Routine Description:
	This routine is a registered callback called before any operation that can modify a file.
	It retrieves the file context and check that it is authorize in "Write" mode, else it blocks the operation.
	This is non-pageable because it could be called on the paging path.
Arguments:
	Data - Pointer to the filter callback data
	FltObjects - Pointer to the structure containing handles to the filter, instance, associated volume and file.
	CompletionContext - Optional context that can be passed to the post callback. NULL in this case.
--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	PKEYSAS_FILE_CTX fileContext = NULL;
	PKEYSAS_INSTANCE_CTX instanceContext = NULL;
	BOOLEAN contextCreated = FALSE;
	BOOLEAN isDirectory = FALSE;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;

	UNREFERENCED_PARAMETER(CompletionContext);


	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: Entered\n"));
	status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo
	);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: FltGetFileNameInformation failed with status: %0x8x\n",
			status));
		status = FLT_POSTOP_FINISHED_PROCESSING;
		goto cleanup;
	}

	FltParseFileNameInformation(nameInfo);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: File Name:%wZ, Extension: %wZ, Volume: %wZ\n",
		nameInfo->Name,
		nameInfo->Extension,
		nameInfo->Volume));

	// Filter call
	// Allow call from our userspace application
	if (IoThreadToProcess(Data->Thread) == KeysasData.UserProcess) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: User process call exit\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	// Don't filter call to directories or volumes
	status = FltIsDirectory(Data->Iopb->TargetFileObject, FltObjects->Instance, &isDirectory);

	if (((Data->Iopb->TargetFileObject->Flags & FO_VOLUME_OPEN) == TRUE) ||
		((Data->Iopb->TargetFileObject->FileName.Length == 0) && (Data->Iopb->TargetFileObject->RelatedFileObject == NULL)) ||
		isDirectory)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: directory 1 exit\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: directory 2 exit\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: directory 3 exit\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Check that the instance is allowed
	// Get the instance context
	status = FltGetInstanceContext(
		Data->Iopb->TargetInstance,
		&instanceContext
	);
	if (!NT_SUCCESS(status)) {
		// There should always be a context for an instance to which the filter is attached
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: FltGetInstanceContext failed with status: %0x8x\n",
			status));
		goto cleanup;
	}

	// Get a read lock on the instance context
	if (!AcquireResourceRead(instanceContext->Resource)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: Failed to acquire instance ressource in read mode\n"));
		FltReleaseContext(instanceContext);
		goto cleanup;
	}

	// Apply authorization state to the call
	if (AUTH_ALLOW_ALL != instanceContext->Authorization) {
		// The instance is blocked, reject the operation
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		FltSetCallbackDataDirty(Data);
		result = FLT_PREOP_COMPLETE;
		ReleaseResource(instanceContext->Resource);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: Instance blocked, operation rejected\n"));
		goto cleanup;
	}
	ReleaseResource(instanceContext->Resource);

	// Get the file context
	status = FindFileContext(Data, &fileContext, &contextCreated);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: FindFileContext failed with status: %0x8x\n",
			status));
		goto cleanup;
	}

	// Get a read lock on the file context
	if (!AcquireResourceRead(fileContext->Resource)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: Failed to acquire file ressource in read mode\n"));
		FltReleaseContext(fileContext);
		goto cleanup;
	}

	// Apply authorization state to the call
	if (AUTH_ALLOW_ALL != fileContext->Authorization) {
		// The file is blocked, reject the operation
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		FltSetCallbackDataDirty(Data);
		result = FLT_PREOP_COMPLETE;
		ReleaseResource(fileContext->Resource);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: File blocked, operation rejected\n"));
		goto cleanup;
	}
	ReleaseResource(fileContext->Resource);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfPreWriteHandler: Operation allowed\n"));
	result = FLT_PREOP_SUCCESS_NO_CALLBACK;

cleanup:
	if (NULL != instanceContext) {
		FltReleaseContext(instanceContext);
	}
	if (NULL != fileContext) {
		FltReleaseContext(fileContext);
	}

	return result;
}

NTSTATUS
KeysasGetFileNameHash(
	_In_ PUNICODE_STRING FileName,
	_Out_ PUCHAR *Hash
)
/***
Routine Description:
	This routine compute the hash of a file name and stores it in a buffer.
	This routine uses the crypto provider initialize in the global KeysasData.
Arguments:
	FileName - Name of the file
	Hash - Pointer to the buffer. The buffer is allocated by the routine. It must be NULL.
Return Value:
	Returns STATUS_SUCCESS if no error occured.
--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	BCRYPT_HASH_HANDLE hashHandle = NULL;

	// Test provided hash pointer and allocate it
	if (NULL == Hash || NULL != *Hash) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasGetFileNameHash: Non null hash buffer\n"));
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	if (NULL == (*Hash = ExAllocatePoolZero(
		NonPagedPool,
		KeysasData.HashLength,
		KEYSAS_MEMORY_TAG
	))) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasGetFileNameHash: Failed to allocate output hash\n"));
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	// Create the hash
	if (!NT_SUCCESS(status = BCryptCreateHash(
		KeysasData.HashProvider,
		&hashHandle,
		NULL,
		0,
		NULL,
		0,
		0
	))) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasGetFileNameHash: Failed to create hash\n"));
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	// Feed the hash with FileName
	if (!NT_SUCCESS(status = BCryptHashData(
		hashHandle,
		(PUCHAR) FileName->Buffer,
		FileName->Length,
		0
	))) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasGetFileNameHash: Failed to run hash\n"));
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	// Finalize the hash in the output buffer
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hashHandle,
		*Hash,
		KeysasData.HashLength,
		0
	))) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasGetFileNameHash: Failed to finalize hash\n"));
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

cleanup:
	if (hashHandle) {
		BCryptDestroyHash(hashHandle);
	}
	/*
	if (NULL != hashObject) {
		ExFreePoolWithTag(hashObject, KEYSAS_MEMORY_TAG);
	}
	*/

	return status;
}

NTSTATUS
KeysasScanFileInUserMode(
	_In_ PUNICODE_STRING FileName,
	_In_ PUCHAR FileID,
	_In_ KEYSAS_FILTER_OPERATION Operation,
	_Out_ KEYSAS_AUTHORIZATION *Authorization
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
	Operation - Operation code for the user app
	Authorization - Authorization status granted by the service
Return Value:
	The status of the operation, hopefully STATUS_SUCCESS.  The common failure
	status will probably be STATUS_INSUFFICIENT_RESOURCES.
--*/

{
	NTSTATUS status = STATUS_SUCCESS;
	PKEYSAS_DRIVER_REQUEST request = NULL;
	ULONG replyLength = 0;

	PAGED_CODE();

	// Set default authorization to pending
	*Authorization = AUTH_PENDING;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: Entered\n"));

	if (NULL == KeysasData.ClientPort) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: Invalid client port\n"));
		return status;
	}

	if (FileName->Length > (KEYSAS_REQUEST_BUFFER_SIZE - KeysasData.HashLength - 1)) {
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

	// Copy the File ID at the start of the request
	memcpy(request->Content, FileID, KeysasData.HashLength);

	// Copy the name of the file in the request
	status = RtlStringCbCopyUnicodeString(
		request->Content + KeysasData.HashLength/2,
		KEYSAS_REQUEST_BUFFER_SIZE * sizeof(WCHAR) - KeysasData.HashLength,
		FileName);
	if (STATUS_SUCCESS != status) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: Failed to convert UNICODE_STRING\n"));
		goto end;
	}
	request->Operation = Operation;
	request->Operation = SCAN_FILE;

	replyLength = sizeof(*request);

	// Send request to userspace
	status = FltSendMessage(
		KeysasData.Filter,
		&KeysasData.ClientPort,
		request,
		FileName->Length+sizeof(KEYSAS_FILTER_OPERATION) + KeysasData.HashLength,
		request,
		&replyLength,
		NULL
	);

	if (STATUS_SUCCESS == status) {
		*Authorization = ((PKEYSAS_REPLY)request)->Result;
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasScanFileInUserMode: Received result\n"));
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