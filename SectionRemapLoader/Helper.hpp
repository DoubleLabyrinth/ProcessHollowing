#pragma once
#include <windows.h>
#include "KernelApis.hpp"
#include "OwnedResource.hpp"

struct FileHandleTraits {
    using HandleType = HANDLE;
    static inline const HandleType InvalidValue = INVALID_HANDLE_VALUE;
    static constexpr auto& Releasor = CloseHandle;
};

struct KernelHandleTraits {
    using HandleType = HANDLE;
    static inline const HandleType InvalidValue = NULL;
    static constexpr auto& Releasor = NtClose;
};

namespace exeLoader {

    PTSTR GetCommandLineStartingFromNthArgv(
        _In_ PTSTR lpszCmdLine, 
        _In_ DWORD Index
    );

    BOOL ValidateExeFile(
        _In_ PVOID lpFileBase,
        _Out_opt_ PIMAGE_DOS_HEADER* lpDosHeader,
        _Out_opt_ PIMAGE_NT_HEADERS* lpNtHeaders,
        _Out_opt_ PIMAGE_SECTION_HEADER* lpSectionHeader
    );

    BOOL AreExesCompatible(
        _In_ PIMAGE_NT_HEADERS FirstExe,
        _In_ PIMAGE_NT_HEADERS SecondExe
    );

    DWORD LaunchHollowProcess(
        _In_ PTSTR lpszCmdLine,
        _Out_opt_ PPROCESS_INFORMATION lpProcessInfo,
        _Out_opt_ PCONTEXT lpRegisterContext,
        _Out_opt_ PVOID* lpImageBase
    );

    DWORD CreateSectionOfImage(
        _In_ PTSTR lpszFileName,
        _Inout_ OwnedResource<FileHandleTraits>& hFile,
        _Inout_ OwnedResource<KernelHandleTraits>& hSection
    );

    DWORD MapViewOfImage(
        _In_ HANDLE hProcess,
        _In_ HANDLE hSection,
        _In_ PVOID* lppBaseAddress,
        _Out_opt_ PSIZE_T lpViewSize
    );

    DWORD UnmapViewOfImage(
        _In_ PVOID lpImageBase
    );

    DWORD UpdateEntryPoint(
        _In_ HANDLE hThread,
        _In_ const CONTEXT* lpContext,
        _In_ PVOID NewEntryPoint
    );

    DWORD ResumeProcess(
        _In_ HANDLE hProcess
    );
}

