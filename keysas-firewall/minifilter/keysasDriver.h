/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	keysasDriver.h

Abstract:

	This filter intercept all operations on files stored on removable media and
	check if they have been validated by a Keysas station.

Environment:

	Kernel mode

--*/

#pragma once

#ifndef _H_KEYSAS_DRIVER_
#define _H_KEYSAS_DRIVER_

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

// Memory Pool Tag
#define KEYSAS_MEMORY_TAG	'eKlF'

// Structure to hold the driver data
typedef struct _KEYSAS_DATA {
	// The object that identifies this driver
	PDRIVER_OBJECT DriverObject;

	// The filter handle
	PFLT_FILTER Filter;

	// Connection port for incomming connections
	PFLT_PORT ServerPort;

	// User process connected to the port
	PEPROCESS UserProcess;

	// Connection port to user-mode
	PFLT_PORT ClientPort;
} KEYSAS_DATA, * PKEYSAS_DATA;

extern KEYSAS_DATA KeysasData;

typedef enum _KEYSAS_AUTHORIZATION {
	AUTH_UNKNOWN = 0,	// Default value
	AUTH_PENDING,		// Authorization request pending
	AUTH_BLOCK,			// Access is blocked
	AUTH_ALLOW_READ,	// Access is allowed in read mode
	AUTH_ALLOW_WARNING,	// Access is allowed but with a warning to the user
	AUTH_ALLOW_ALL		// Access is allowed for all operations
} KEYSAS_AUTHORIZATION;

#endif // !_H_KEYSAS_DRIVER_
