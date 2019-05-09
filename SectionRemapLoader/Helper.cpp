#include "Helper.hpp"
#include <tchar.h>
#include <utility>

namespace exeLoader {

    //
    // lpszCmdLine must be a valid command line string.
    //
    PTSTR GetCommandLineStartingFromNthArgv(_In_ PTSTR lpszCmdLine, _In_ DWORD Index) {
        DWORD CurrentIndex = 0;

        bool IsDoubleQuoted = false;
        for (DWORD i = 0; lpszCmdLine[i]; ++i) {
            if (CurrentIndex == Index)
                return &lpszCmdLine[i];

            switch (lpszCmdLine[i]) {
            case TEXT('\t'):
            case TEXT(' '):
                while (_istspace(lpszCmdLine[i + 1]))
                    ++i;
                if (IsDoubleQuoted == false)
                    ++CurrentIndex;
                break;
            case TEXT('"'):
                if (i > 0) {
                    DWORD p = i;
                    while (lpszCmdLine[p - 1] == TEXT('\\'))
                        --p;
                    IsDoubleQuoted = (i - p) % 2 == 0 ? !IsDoubleQuoted : IsDoubleQuoted;
                } else {
                    IsDoubleQuoted = !IsDoubleQuoted;
                }
                break;
            default:
                break;
            }
        }

        return nullptr;
    }

    BOOL ValidateExeFile(_In_ PVOID lpMappedImageBase, 
                         _Out_opt_ PIMAGE_DOS_HEADER* lpDosHeader, 
                         _Out_opt_ PIMAGE_NT_HEADERS* lpNtHeaders,
                         _Out_opt_ PIMAGE_SECTION_HEADER* lpSectionHeader) {
        DWORD dwOffset = 0;
        PBYTE pbMappedImageBase = reinterpret_cast<PBYTE>(lpMappedImageBase);

        PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpMappedImageBase);
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return FALSE;

        PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pbMappedImageBase + DosHeader->e_lfanew);
        if (NtHeaders->Signature != IMAGE_NT_SIGNATURE || NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
            return FALSE;

        PIMAGE_SECTION_HEADER SectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(
            pbMappedImageBase + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_NT_HEADERS::OptionalHeader) + NtHeaders->FileHeader.SizeOfOptionalHeader
        );

        if (lpDosHeader)
            *lpDosHeader = DosHeader;
        if (lpNtHeaders)
            *lpNtHeaders = NtHeaders;
        if (lpSectionHeader)
            *lpSectionHeader = SectionHeader;

        return TRUE;
    }

    BOOL AreExesCompatible(_In_ PIMAGE_NT_HEADERS FirstExe, _In_ PIMAGE_NT_HEADERS SecondExe) {
        if (FirstExe->FileHeader.Machine != SecondExe->FileHeader.Machine)
            return FALSE;

        return TRUE;
    }

    DWORD LaunchHollowProcess(_In_ PTSTR lpszCmdLine,
                              _Out_opt_ PPROCESS_INFORMATION lpProcessInfo,
                              _Out_opt_ PCONTEXT lpRegisterContext,
                              _Out_opt_ PVOID* lpImageBase) {
        DWORD dwStatus;
        NTSTATUS ntStatus;
        PROCESS_INFORMATION ProcessInfo = {};
        STARTUPINFO StartupInfo = { sizeof(STARTUPINFO) };

        if (CreateProcess(NULL,
                          lpszCmdLine,
                          NULL,
                          NULL,
                          FALSE,
                          CREATE_SUSPENDED,
                          NULL,
                          NULL,
                          &StartupInfo,
                          &ProcessInfo) == FALSE) {
            return GetLastError();
        }

        CONTEXT RegisterContext = {};
        RegisterContext.ContextFlags = CONTEXT_INTEGER;
        if (GetThreadContext(ProcessInfo.hThread, &RegisterContext) == FALSE) {
            dwStatus = GetLastError();
            TerminateProcess(ProcessInfo.hProcess, 0);
            CloseHandle(ProcessInfo.hThread);
            CloseHandle(ProcessInfo.hProcess);
            return dwStatus;
        }

#ifdef _M_IX86
        PPEB lpPeb = reinterpret_cast<PPEB>(RegisterContext.Ebx);
#elif defined(_M_X64)
        PPEB lpPeb = reinterpret_cast<PPEB>(RegisterContext.Rdx);
#endif
        PVOID ImageBase;

        if (!ReadProcessMemory(ProcessInfo.hProcess, reinterpret_cast<PBYTE>(&lpPeb->Ldr) - sizeof(PVOID), &ImageBase, sizeof(PVOID), NULL)) {
            dwStatus = GetLastError();
            TerminateProcess(ProcessInfo.hProcess, 0);
            CloseHandle(ProcessInfo.hThread);
            CloseHandle(ProcessInfo.hProcess);
            return dwStatus;
        }

        ntStatus = NtUnmapViewOfSection(ProcessInfo.hProcess, ImageBase);
        if (!NT_SUCCESS(ntStatus)) {
            return RtlNtStatusToDosError(ntStatus);
        }

        if (lpProcessInfo)
            *lpProcessInfo = ProcessInfo;
        if (lpRegisterContext)
            *lpRegisterContext = RegisterContext;
        if (lpImageBase)
            *lpImageBase = ImageBase;

        return ERROR_SUCCESS;
    }

    DWORD CreateSectionOfImage(_In_ PTSTR lpszFileName,
                               _Inout_ OwnedResource<FileHandleTraits>& hFile,
                               _Inout_ OwnedResource<KernelHandleTraits>& hSection) {
        NTSTATUS ntStatus;
        OwnedResource<FileHandleTraits> _hFile;
        OwnedResource<KernelHandleTraits> _hSection;

        _hFile.TakeOver(
            CreateFile(lpszFileName, 
                       GENERIC_READ | GENERIC_EXECUTE, 
                       FILE_SHARE_READ, 
                       NULL, 
                       OPEN_EXISTING, 
                       NULL, 
                       NULL)
        );
        if (_hFile.IsValid() == false) {
            return GetLastError();
        }

        ntStatus = NtCreateSection(_hSection.GetAddress(), 
                                   SECTION_ALL_ACCESS, 
                                   NULL, 
                                   NULL, 
                                   PAGE_EXECUTE_WRITECOPY, 
                                   SEC_IMAGE, 
                                   _hFile);
        if (!NT_SUCCESS(ntStatus)) {
            return RtlNtStatusToDosError(ntStatus);
        }

        hFile = std::move(_hFile);
        hSection = std::move(_hSection);

        return ERROR_SUCCESS;
    }

    DWORD MapViewOfImage(HANDLE hProcess, HANDLE hSection, PVOID* lppBaseAddress, PSIZE_T lpViewSize) {
        NTSTATUS ntStatus;
        SIZE_T ViewSize = 0;

        ntStatus = NtMapViewOfSection(hSection, 
                                      hProcess, 
                                      lppBaseAddress, 
                                      NULL, 
                                      NULL,
                                      NULL, 
                                      &ViewSize, 
                                      ViewUnmap,
                                      NULL, 
                                      PAGE_EXECUTE_WRITECOPY);
        if (!NT_SUCCESS(ntStatus)) {
            if (lpViewSize)
                *lpViewSize = 0;
            return RtlNtStatusToDosError(ntStatus);
        } else {
            if (lpViewSize)
                *lpViewSize = ViewSize;
            return ERROR_SUCCESS;
        }
    }

    DWORD UnmapViewOfImage(_In_ PVOID lpImageBase) {
        NTSTATUS ntStatus = NtUnmapViewOfSection(GetCurrentProcess(), lpImageBase);
        if (!NT_SUCCESS(ntStatus)) {
            return RtlNtStatusToDosError(ntStatus);
        } else {
            return ERROR_SUCCESS;
        }
    }

    DWORD UpdateEntryPoint(_In_ HANDLE hThread, 
                           _In_ const CONTEXT* lpContext,
                           _In_ PVOID NewEntryPoint) {
        CONTEXT NewConext = *lpContext;
#ifdef _M_IX86
        NewConext.Eax = reinterpret_cast<DWORD>(NewEntryPoint);
#elif defined(_M_X64)
        NewConext.Rcx = reinterpret_cast<DWORD64>(NewEntryPoint);
#endif
        if (!SetThreadContext(hThread, &NewConext)) {
            return GetLastError();
        } else {
            return ERROR_SUCCESS;
        }
    }

    DWORD ResumeProcess(_In_ HANDLE hProcess) {
        NTSTATUS ntStatus = NtResumeProcess(hProcess);
        if (!NT_SUCCESS(ntStatus)) {
            return RtlNtStatusToDosError(ntStatus);
        } else {
            return ERROR_SUCCESS;
        }
    }
}

