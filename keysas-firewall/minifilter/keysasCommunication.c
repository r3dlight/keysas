/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	keysasCommunication.c

Abstract:

	Contains the function to connect and disconnect communication port with the user.

Environment:

	Kernel mode

--*/

#include "keysasCommunication.h"

#include <fltKernel.h>
#include <ntddstor.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include <wdm.h>

#include "keysasDriver.h"
#include "keysasFile.h"

// Name of the port used to communicate with user space
const PWSTR KeysasPortName = L"\\KeysasPort";

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KeysasPortConnect)
#pragma alloc_text(PAGE, KeysasPortDisconnect)
#pragma alloc_text(PAGE, KeysasPortNotify)
#endif

NTSTATUS
KeysasInitPort(

)
/*++
Routine Description
	Initialize the communication ports
Arguments
Return Value
	STATUS_SUCCESS - if the initialization is successful
--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING uniPortName = { 0 };
	PSECURITY_DESCRIPTOR sd = NULL;
	OBJECT_ATTRIBUTES oa = { 0 };

	RtlInitUnicodeString(&uniPortName, KeysasPortName);
	// Secure the port so only ADMINs & SYSTEM can access it
	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status)) {
		InitializeObjectAttributes(
			&oa,
			&uniPortName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd
		);

		status = FltCreateCommunicationPort(
			KeysasData.Filter,
			&KeysasData.ServerPort,
			&oa,
			NULL,
			KeysasPortConnect,
			KeysasPortDisconnect,
			KeysasPortNotify,
			1
		);

		FltFreeSecurityDescriptor(sd);
	}
	else {
		status = STATUS_UNSUCCESSFUL;
	}

	return status;
}

NTSTATUS
KeysasPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionCookie
)
/*++
Routine Description
	This is called when user-mode connects to the server port - to establish a
	connection
Arguments
	ClientPort - This is the client connection port that will be used to
		send messages from the filter
	ServerPortCookie - The context associated with this port when the
		minifilter created this port.
	ConnectionContext - Context from entity connecting to this port (most likely
		your user mode service)
	SizeofContext - Size of ConnectionContext in bytes
	ConnectionCookie - Context to be passed to the port disconnect routine.
Return Value
	STATUS_SUCCESS - to accept the connection
--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	FLT_ASSERT(KeysasData.ClientPort == NULL);
	FLT_ASSERT(KeysasData.UserProcess == NULL);

	// Set the user process and port
	KeysasData.UserProcess = PsGetCurrentProcess();
	KeysasData.ClientPort = ClientPort;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!keysasPortConnect: Connected user, process=0x%p, port=0x%p\n",
		KeysasData.UserProcess,
		KeysasData.ClientPort));

	return STATUS_SUCCESS;
}

VOID
KeysasPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
)
/*++
Routine Description
	This is called when the connection is torn-down. We use it to close our
	handle to the connection
Arguments
	ConnectionCookie - Context from the port connect routine
Return value
	None
--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!keysasPortDisconnect: Connected user, port=0x%p\n", KeysasData.ClientPort));

	FltCloseClientPort(KeysasData.Filter, &KeysasData.ClientPort);

	KeysasData.UserProcess = NULL;
}

NTSTATUS
KeysasPortNotify (
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferLength
)
/*++
Routine Description
	This is called when a request is received from userspace
Arguments
	PortCookie - Cookie that identifies the user, not use as there is only one connection from the service
	InputBuffer - Buffer containing the request, it is allocated by the userspace
	InputBufferLength - Length of the input buffer
	OutputBuffer - Buffer for the response, it is allocated by the userspace
	OutputBufferLength - Length of the output buffer
	ReturnOutputBufferlength - Length of the response
Return value
	None
--*/
{
	UNREFERENCED_PARAMETER(ConnectionCookie);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferSize);

	PLIST_ENTRY scan, next;
	PKEYSAS_FILE_CTX fileCtx = NULL;
	KIRQL kIrql;
	PUCHAR inputBuffer = (PUCHAR)InputBuffer;

	ReturnOutputBufferLength = 0;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: Entered\n"));

	// Test that the input buffer contains at least 33 bytes
	if (33 > InputBufferSize || NULL == InputBuffer) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: Not enough input data\n"));
		return STATUS_UNSUCCESSFUL;
	}

	// Test if the file context list is empty
	if (TRUE == IsListEmpty(&KeysasData.FileCtxListHead)) {
		// TODO - Send response to userspace
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: File context list is empty\n"));
		return STATUS_SUCCESS;
	}

	kIrql = KeGetCurrentIrql();

	// Get lock on the list
	KeAcquireSpinLock(&KeysasData.FileCtxListLock, &kIrql);

	// Go through the list to find the context
	for (scan = (KeysasData.FileCtxListHead).Flink, next = scan->Flink; scan != &(KeysasData.FileCtxListHead); scan = next, next = scan->Flink) {
		fileCtx = CONTAINING_RECORD(scan, KEYSAS_FILE_CTX, FileCtxList);

		if (32 == RtlCompareMemory(fileCtx->FileID, inputBuffer, 32)) {
			// Changed the authorization status to the one provided by the service
			fileCtx->Authorization = inputBuffer[32];
			break;
		}
	}

	KeReleaseSpinLock(&KeysasData.FileCtxListLock, kIrql);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Keysas!KeysasPortNotify: Done\n"));

	// If the context is found apply the request
	
	return STATUS_SUCCESS;
}