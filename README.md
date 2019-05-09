# Process Hollowing

## 1. SectionRemapLoader

__SectionRemapLoader__ uses `NtUnmapViewOfSection`, `NtCreateSection` and `NtMapViewOfSection` to perform process hollowing. This way is much more easier, but requires a valid PE image file on disk.

__MAKE SURE ARCHITECTURE MATCHES.__ i.e. launch 32-bits process with `SectionRemapLoader.exe` built in 32-bits mode OR launch 64-bits process with `SectionRemapLoader.exe` built in 64-bits mode.

```
Usage:
    SectionRemapLoader.exe <exe to load> <exe to launch> [args...]
```

__Example:__

```
$ .\SectionRemapLoader.exe C:\Windows\write.exe C:\Windows\Notepad.exe
```

