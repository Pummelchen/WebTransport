# Windows 11 C++ Build Support

Primary output:

- DLL/import library: `CPP/out/windows11/install/bin/` and `CPP/out/windows11/install/lib/`
- Headers: `CPP/out/windows11/install/include/`
- CMake package files: `CPP/out/windows11/install/lib/cmake/`

Build command from PowerShell:

```powershell
.\CPP\platform\windows11\compile-dll.ps1
```

The script configures a Release shared-library build with CMake and installs it under `CPP/out/windows11/install`.
