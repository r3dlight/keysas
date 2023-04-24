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

#ifndef _H_KEYSAS_INSTANCE_
#define _H_KEYSAS_INSTANCE_

#include "keysasDriver.h"

// Instance context data structure
typedef struct _KEYSAS_INSTANCE_CTX {
	// Authorization state of the instance
	KEYSAS_AUTHORIZATION Authorization;

	// Lock used to protect the context
	PERESOURCE Resource;
} KEYSAS_INSTANCE_CTX, * PKEYSAS_INSTANCE_CTX;

#define KEYSAS_INSTANCE_CTX_SIZE	sizeof(KEYSAS_INSTANCE_CTX)

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

NTSTATUS
KfInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

VOID
KfInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
KfInstanceContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
);

#endif _H_KEYSAS_INSTANCE_