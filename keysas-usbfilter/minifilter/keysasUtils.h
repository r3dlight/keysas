/*++

Copyright (c) 2023 Luc Bonnafoux

Module Name:

	keysasUtils.c

Abstract:

	Contains generic utility functions

Environment:

	Kernel mode

--*/

#pragma once

#ifndef _H_KEYSAS_UTILS_
#define _H_KEYSAS_UTILS_

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

// Acquire ressource in write mode
// Wait for the lock if not available
BOOLEAN
_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
AcquireResourceWrite(
	_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_exclusive_lock_(*_Curr_) PERESOURCE Resource
);

// Acquire ressource in read mode
// Wait for the lock if not available
BOOLEAN
_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
AcquireResourceRead(
	_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_shared_lock_(*_Curr_) PERESOURCE Resource
);

// Realease a lock
VOID
_Releases_lock_(_Global_critical_region_)
_Requires_lock_held_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
ReleaseResource(
	_Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) PERESOURCE Resource
);

#endif // _H_KEYSAS_UTILS_