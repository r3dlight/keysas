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

/*
	TODO:
		- Assign all values in the declaration with defaults
		- Rename memory pool tags
*/

#include <fltKernel.h>
#include <ntddstor.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include <wdm.h>

#include "keysasDriver.h"
#include "keysasUtils.h"
#include "keysasCommunication.h"
#include "keysasInstance.h"
#include "keysasFile.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

/************************************************************************
	Global variables
*************************************************************************/

// Global instance of the driver data
KEYSAS_DATA KeysasData = { 0 };

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
KfUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, KfUnload)
#endif

//
//  operation registration
//
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	// IRP_MJ_WRITE
	{IRP_MJ_WRITE,
	  0,
	  KfPreWriteHandler,
	  NULL},

	{ IRP_MJ_CREATE,
	  0,
	  KfPreCreateHandler,
	  KfPostCreateHandler },

	{ IRP_MJ_OPERATION_END }
};

//
// Context callback registration
//
const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_INSTANCE_CONTEXT,
	  0,
	  KfInstanceContextCleanup,
	  KEYSAS_INSTANCE_CTX_SIZE,
	  KEYSAS_MEMORY_TAG },

	{ FLT_FILE_CONTEXT,
	  0,
	  KfFileContextCleanup,
	  KEYSAS_FILE_CTX_SIZE,
	  KEYSAS_MEMORY_TAG },

	{ FLT_CONTEXT_END }
};

//
//  This defines what we want to filter with FltMgr
//
CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,			//  Version
	0,									//  Flags

	ContextRegistration,				//  Context
	Callbacks,							//  Operation callbacks

	KfUnload,							//  MiniFilterUnload

	KfInstanceSetup,					//  InstanceSetup
	KfInstanceQueryTeardown,			//  InstanceQueryTeardown
	KfInstanceTeardownStart,			//  InstanceTeardownStart
	KfInstanceTeardownComplete,			//  InstanceTeardownComplete

	NULL,								//  GenerateFileName
	NULL,								//  GenerateDestinationFileName
	NULL								//  NormalizeNameComponent

};

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

	This is the initialization routine for this Keysas driver.  This
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
	NTSTATUS status = STATUS_SUCCESS;
	DWORD cbData = 0;

	UNREFERENCED_PARAMETER(RegistryPath);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas: DriverEntry\n"));

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	// Initialize global data structure
	RtlZeroMemory(&KeysasData, sizeof(KeysasData));
	InitializeListHead(&KeysasData.FileCtxListHead);
	KeInitializeSpinLock(&KeysasData.FileCtxListLock);

	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&KeysasData.HashProvider,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0
	))) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas: Failed to get hash provider\n"));
		return status;
	}

	// Get the internal hash object size
	if (!NT_SUCCESS(status = BCryptGetProperty(
		KeysasData.HashProvider,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR) &KeysasData.HashObjectSize,
		sizeof(DWORD),
		&cbData,
		0
	))) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas: Failed to get hash object size\n"));
		return status;
	}

	// Get the hash size
	if (!NT_SUCCESS(status = BCryptGetProperty(
		KeysasData.HashProvider,
		BCRYPT_HASH_LENGTH,
		(PUCHAR)&KeysasData.HashLength,
		sizeof(DWORD),
		&cbData,
		0
	))) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas: Failed to get hash length\n"));
		return status;
	}

	// Register the filter's callbacks
	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&KeysasData.Filter);
	FLT_ASSERT(NT_SUCCESS(status));

	// Create the communication port
	status = KeysasInitPort();

	if (NT_SUCCESS(status)) {
		//
		//  Start filtering i/o
		//

		status = FltStartFiltering(KeysasData.Filter);

		if (NT_SUCCESS(status)) {
			return STATUS_SUCCESS;
		}

		FltCloseCommunicationPort(KeysasData.ServerPort);
	}

	FltUnregisterFilter(KeysasData.Filter);

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

	FltCloseCommunicationPort(KeysasData.ServerPort);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfUnload: Closed server port\n"));

	// Release crypto provider
	BCryptCloseAlgorithmProvider(KeysasData.HashProvider, 0);

	// TODO - Release all context in the list

	FltUnregisterFilter(KeysasData.Filter);
	KeysasData.Filter = NULL;
	KeysasData.ServerPort = NULL;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KfUnload: Done\n"));

	return STATUS_SUCCESS;
}