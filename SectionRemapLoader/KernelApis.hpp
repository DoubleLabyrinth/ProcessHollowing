#pragma once
#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll")

#ifdef __cplusplus
extern "C" {
#endif

    __kernel_entry NTSTATUS
    NTAPI
    NtCreateSection(
        _Out_ PHANDLE SectionHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PLARGE_INTEGER MaximumSize,
        _In_ ULONG SectionPageProtection,
        _In_ ULONG AllocationAttributes,
        _In_opt_ HANDLE FileHandle
    );

    typedef enum _SECTION_INHERIT {
        ViewShare = 1,
        ViewUnmap = 2
    } SECTION_INHERIT;

    __kernel_entry NTSTATUS
    NTAPI
    NtMapViewOfSection(
        _In_ HANDLE SectionHandle,
        _In_ HANDLE ProcessHandle,
        _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
        _In_ ULONG_PTR ZeroBits,
        _In_ SIZE_T CommitSize,
        _Inout_opt_ PLARGE_INTEGER SectionOffset,
        _Inout_ PSIZE_T ViewSize,
        _In_ SECTION_INHERIT InheritDisposition,
        _In_ ULONG AllocationType,
        _In_ ULONG Win32Protect
    );

    __kernel_entry NTSTATUS
    NTAPI
    NtUnmapViewOfSection(
        _In_ HANDLE ProcessHandle,
        _In_ PVOID  BaseAddress
    );

    __kernel_entry NTSTATUS
    NTAPI
    NtResumeProcess(
        _In_ HANDLE ProcessHandle
    );

#ifdef __cplusplus
}
#endif

