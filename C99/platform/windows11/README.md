# Windows 11 C99 Build Support

Primary output:

- DLL/import library: `C99/out/windows11/install/bin/` and `C99/out/windows11/install/lib/`
- Static library: `C99/out/windows11/install/lib/`
- Headers: `C99/out/windows11/install/include/`
- CMake package files: `C99/out/windows11/install/lib/cmake/`

Build command from PowerShell:

```powershell
.\C99\platform\windows11\compile-dll.ps1
```

The script configures a Release shared-library build with CMake and installs it under `C99/out/windows11/install`.
