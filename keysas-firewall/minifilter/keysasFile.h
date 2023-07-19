/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	keysasInstance.h

Abstract:

	Contains the definitions and the operation for a filter instance

Environment:

	Kernel mode

--*/

#pragma once

#ifndef _H_KEYSAS_FILE_
#define _H_KEYSAS_FILE_

#include "keysasDriver.h"
#include "keysasCommunication.h"

typedef struct _KEYSAS_FILE_CTX {
	// Authorization state of the file
	KEYSAS_AUTHORIZATION Authorization;

	// SHA256 of the file name, used as a reference to perform context lookup
	PUCHAR FileID;

	// Lock used to protect the context
	PERESOURCE Resource;

	// Pointers to the context list
	LIST_ENTRY FileCtxList;

	// TODO - Add reference to the volume so that it can be freed when the volume is released
} KEYSAS_FILE_CTX, * PKEYSAS_FILE_CTX;

#define KEYSAS_FILE_CTX_SIZE	sizeof(KEYSAS_FILE_CTX)

VOID
KfFileContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
);

NTSTATUS
KeysasScanFileInUserMode(
	_In_ PUNICODE_STRING FileName,
	_In_ PUCHAR FileID,
	_In_ KEYSAS_FILTER_OPERATION Operation,
	_Out_ KEYSAS_AUTHORIZATION* Authorization
);

FLT_PREOP_CALLBACK_STATUS
KfPreCreateHandler(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
KfPostCreateHandler(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS
FindFileContext(
	_In_ PFLT_CALLBACK_DATA Data,
	_Outptr_ PKEYSAS_FILE_CTX* FileContext,
	_Out_opt_ PBOOLEAN ContextCreated
);

NTSTATUS
KeysasGetFileNameHash(
	_In_ PUNICODE_STRING FileName,
	_Out_ PUCHAR *Hash
);

#endif