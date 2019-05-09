#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include "Helper.hpp"

void Help() {
    _putts(TEXT("Usage:"));
    _putts(TEXT("    SectionRemapLoader.exe <exe to load> <exe to launch> [args...]"));
    _putts(TEXT(""));
}

int _tmain(int argc, PTSTR argv[]) {
    if (argc >= 3) {
        DWORD dwStatus;

        OwnedResource<FileHandleTraits>     hSrcExeFile;
        OwnedResource<KernelHandleTraits>   hSrcExeSection;
        PVOID                               lpSrcExe = NULL;
        PIMAGE_DOS_HEADER                   lpSrcExeDosHeader;
        PIMAGE_NT_HEADERS                   lpSrcExeNtHeaders;
        ULONG_PTR                           SrcExeEntryPointRva;
        
        OwnedResource<FileHandleTraits>     hDstExeFile;
        OwnedResource<KernelHandleTraits>   hDstExeSection;
        PVOID                               lpDstExe = NULL;
        PIMAGE_DOS_HEADER                   lpDstExeDosHeader;
        PIMAGE_NT_HEADERS                   lpDstExeNtHeaders;

        PROCESS_INFORMATION ProcessInfo;
        CONTEXT RegisterContext;
        PVOID ProcessImageBase = NULL;

        dwStatus = exeLoader::CreateSectionOfImage(argv[1], hSrcExeFile, hSrcExeSection);
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: Failed to create section for %s fails. CODE: 0x%.8X\n"), argv[1], dwStatus);
            return dwStatus;
        } else {
            _tprintf_s(TEXT("[+] main: Create section for %s successfully.\n"), argv[1]);
        }

        dwStatus = exeLoader::CreateSectionOfImage(argv[2], hDstExeFile, hDstExeSection);
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: Failed to create section for %s fails. CODE: 0x%.8X\n"), argv[2], dwStatus);
            return dwStatus;
        } else {
            _tprintf_s(TEXT("[+] main: Create section for %s successfully.\n"), argv[2]);
        }

        dwStatus = exeLoader::MapViewOfImage(GetCurrentProcess(), hSrcExeSection, &lpSrcExe, NULL);
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: Failed to map view of %s. CODE: 0x%.8X\n"), argv[1], dwStatus);
            return dwStatus;
        } else {
            _tprintf_s(TEXT("[+] main: Map view of %s successfully. lpSrcExe = %p\n"), argv[1], lpSrcExe);
        }

        dwStatus = exeLoader::MapViewOfImage(GetCurrentProcess(), hDstExeSection, &lpDstExe, NULL);
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: Failed to map view of %s. CODE: 0x%.8X\n"), argv[2], dwStatus);
            return dwStatus;
        } else {
            _tprintf_s(TEXT("[+] main: Map view of %s successfully. lpDstExe = %p\n"), argv[2], lpDstExe);
        }

        if (exeLoader::ValidateExeFile(lpSrcExe, &lpSrcExeDosHeader, &lpSrcExeNtHeaders, NULL) == FALSE) {
            _tprintf_s(TEXT("[-] main: ValidateExeFile for %s failed.\n"), argv[1]);
            return -1;
        } else {
            _tprintf_s(TEXT("[+] main: ValidateExeFile for %s succeeded.\n"), argv[1]);
        }

        if (exeLoader::ValidateExeFile(lpDstExe, &lpDstExeDosHeader, &lpDstExeNtHeaders, NULL) == FALSE) {
            _tprintf_s(TEXT("[-] main: ValidateExeFile for %s failed.\n"), argv[2]);
            return -1;
        } else {
            _tprintf_s(TEXT("[+] main: ValidateExeFile for %s succeeded.\n"), argv[2]);
        }

        if (exeLoader::AreExesCompatible(lpSrcExeNtHeaders, lpDstExeNtHeaders) == FALSE) {
            _tprintf_s(TEXT("[-] main: Exe compatible check failed.\n"));
            return -1;
        } else {
            _tprintf_s(TEXT("[+] main: Exe compatible check passed.\n"));
        }

        SrcExeEntryPointRva = lpSrcExeNtHeaders->OptionalHeader.AddressOfEntryPoint;

        dwStatus = exeLoader::UnmapViewOfImage(lpSrcExe);
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: Failed to unmap view of %s. CODE: 0x%.8X\n"), argv[1], dwStatus);
            return dwStatus;
        } else {
            _tprintf_s(TEXT("[+] main: Unmap view of %s successfully.\n"), argv[1]);
        }

        dwStatus = exeLoader::UnmapViewOfImage(lpDstExe);
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: Failed to unmap view of %s. CODE: 0x%.8X\n"), argv[2], dwStatus);
            return dwStatus;
        } else {
            _tprintf_s(TEXT("[+] main: Unmap view of %s successfully.\n"), argv[2]);
        }

        dwStatus = exeLoader::LaunchHollowProcess(
            exeLoader::GetCommandLineStartingFromNthArgv(GetCommandLine(), 2),
            &ProcessInfo,
            &RegisterContext,
            &ProcessImageBase
        );
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: Failed to launch hollow process for %s. CODE: 0x%.8X\n"), argv[2], dwStatus);
            return dwStatus;
        } else {
            _tprintf_s(TEXT("[+] main: [PID = %d][TID = %d] Launch hollow process for %s successfully.\n"),
                       ProcessInfo.dwProcessId,
                       ProcessInfo.dwThreadId,
                       argv[2]);
            _tprintf_s(TEXT("[*] main: [PID = %d][TID = %d] ProcessImageBase = %p\n"),
                       ProcessInfo.dwProcessId,
                       ProcessInfo.dwThreadId,
                       ProcessImageBase);
        }

        dwStatus = exeLoader::MapViewOfImage(ProcessInfo.hProcess, hSrcExeSection, &ProcessImageBase, NULL);
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: [PID = %d][TID = %d] Failed to map view of %s. CODE: 0x%.8X\n"), 
                       ProcessInfo.dwProcessId,
                       ProcessInfo.dwThreadId,
                       argv[1], 
                       dwStatus);
            TerminateProcess(ProcessInfo.hProcess, 0);
            CloseHandle(ProcessInfo.hThread);
            CloseHandle(ProcessInfo.hProcess);
            return dwStatus;
        } else {
            _tprintf_s(TEXT("[+] main: [PID = %d][TID = %d] Map view of %s successfully. ImageBase = %p\n"),
                       ProcessInfo.dwProcessId,
                       ProcessInfo.dwThreadId,
                       argv[1],
                       ProcessImageBase);
        }

        dwStatus = exeLoader::UpdateEntryPoint(
            ProcessInfo.hThread,
            &RegisterContext,
            reinterpret_cast<PBYTE>(ProcessImageBase) + SrcExeEntryPointRva
        );
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: [PID = %d][TID = %d] Failed to update entry point. CODE: 0x%.8X\n"),
                       ProcessInfo.dwProcessId,
                       ProcessInfo.dwThreadId,
                       dwStatus);
            TerminateProcess(ProcessInfo.hProcess, 0);
            CloseHandle(ProcessInfo.hThread);
            CloseHandle(ProcessInfo.hProcess);
            return dwStatus;
        } else {
            _tprintf_s(TEXT("[+] main: [PID = %d][TID = %d] Update entry point successfully.\n"),
                       ProcessInfo.dwProcessId,
                       ProcessInfo.dwThreadId);
        }

        dwStatus = exeLoader::ResumeProcess(ProcessInfo.hProcess);
        if (dwStatus != ERROR_SUCCESS) {
            _tprintf_s(TEXT("[-] main: [PID = %d][TID = %d] Failed to resume process. CODE: 0x%.8X\n"),
                       ProcessInfo.dwProcessId,
                       ProcessInfo.dwThreadId,
                       dwStatus);
        } else {
            _tprintf_s(TEXT("[+] main: [PID = %d][TID = %d] Resume process successfully.\n"),
                       ProcessInfo.dwProcessId,
                       ProcessInfo.dwThreadId);
        }

        CloseHandle(ProcessInfo.hThread);
        CloseHandle(ProcessInfo.hProcess);
    } else {
        Help();
    }
    return 0;
}


