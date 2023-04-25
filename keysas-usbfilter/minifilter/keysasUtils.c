#include "keysasUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AcquireResourceWrite)
#pragma alloc_text(PAGE, AcquireResourceRead)
#pragma alloc_text(PAGE, ReleaseResource)
#endif

BOOLEAN
_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
AcquireResourceWrite(
	_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_exclusive_lock_(*_Curr_) PERESOURCE Resource
)
{
	PAGED_CODE();
	if ((KeGetCurrentIrql() <= APC_LEVEL)
		&& (ExIsResourceAcquiredExclusiveLite(Resource)
			|| !ExIsResourceAcquiredSharedLite(Resource))) {
		KeEnterCriticalRegion();
		(VOID)ExAcquireResourceExclusiveLite(Resource, TRUE);
		return TRUE;
	}
	return FALSE;
}

BOOLEAN
_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
AcquireResourceRead(
	_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_shared_lock_(*_Curr_) PERESOURCE Resource
)
{
	PAGED_CODE();
	if (KeGetCurrentIrql() <= APC_LEVEL) {
		KeEnterCriticalRegion();
		(VOID)ExAcquireResourceSharedLite(Resource, TRUE);
		return TRUE;
	}
	return FALSE;
}

VOID
_Releases_lock_(_Global_critical_region_)
_Requires_lock_held_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
ReleaseResource(
	_Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_) PERESOURCE Resource
)
{
	PAGED_CODE();
	if ((KeGetCurrentIrql() <= APC_LEVEL)
		&& (ExIsResourceAcquiredExclusiveLite(Resource)
			|| ExIsResourceAcquiredSharedLite(Resource))) {
		ExReleaseResourceLite(Resource);
		KeLeaveCriticalRegion();
	}
}