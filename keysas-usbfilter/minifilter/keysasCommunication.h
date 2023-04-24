/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	keysasCommunication.h

Abstract:

	Contains the definitions for the communication interface with the user app

Environment:

	Kernel mode

--*/

#pragma once

#ifndef _H_KEYSAS_COMMUNICATION_
#define _H_KEYSAS_COMMUNICATION_

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntdef.h>

#define KEYSAS_REQUEST_BUFFER_SIZE 1024

// Operation code for the request to userland
typedef enum _KEYSAS_FILTER_OPERATION {
	SCAN_FILE = 0,				// Validate the signature of the file and the report
	USER_ALLOW_FILE,			// Ask user to allow the file
	USER_ALLOW_USB_ALL,			// Ask user to allow complete access the USB drive
	USER_ALLOW_USB_WITH_WARNING // Ask user to allow access to USB drive with warning on file opening
} KEYSAS_FILTER_OPERATION;

// Structure of a request from the driver to user space
typedef struct _KEYSAS_DRIVER_REQUEST {
	// Operation to be executed by the user app
	KEYSAS_FILTER_OPERATION Operation;
	// Content of the request
	WCHAR Content[KEYSAS_REQUEST_BUFFER_SIZE];
} KEYSAS_DRIVER_REQUEST, * PKEYSAS_DRIVER_REQUEST;

// Structure of a reply from user space
typedef struct _KEYSAS_REPLY {
	// Result of the operation
	// allow or not usb or file
	BOOLEAN Result;
} KEYSAS_REPLY, * PKEYSAS_REPLY;

NTSTATUS
KeysasInitPort();

NTSTATUS
KeysasPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionCookie
);

VOID
KeysasPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
);

#endif // _H_KEYSAS_COMMUNICATION
