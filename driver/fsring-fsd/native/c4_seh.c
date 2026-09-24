#include <ntifs.h>

NTSTATUS FsRingProbeAndLockPagesSeh(
    PMDL mdl,
    KPROCESSOR_MODE access_mode,
    LOCK_OPERATION operation)
{
    __try {
        MmProbeAndLockPages(mdl, access_mode, operation);
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
}

PVOID FsRingMapLockedPagesSeh(
    PMDL mdl,
    KPROCESSOR_MODE access_mode,
    MEMORY_CACHING_TYPE cache_type,
    PVOID requested_address,
    ULONG bugcheck_on_failure,
    ULONG priority,
    NTSTATUS *status)
{
    __try {
        PVOID address = MmMapLockedPagesSpecifyCache(
            mdl, access_mode, cache_type, requested_address,
            bugcheck_on_failure, priority);
        *status = address != NULL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
        return address;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *status = STATUS_INSUFFICIENT_RESOURCES;
        return NULL;
    }
}
