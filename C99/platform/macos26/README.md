# macOS 26 C99 Build Support

Primary output:

- Shared library: `C99/out/macos26/install/lib/`
- Static library: `C99/out/macos26/install/lib/`
- Headers: `C99/out/macos26/install/include/`
- CMake package files: `C99/out/macos26/install/lib/cmake/`

Build command:

```sh
./C99/platform/macos26/compile-dylib.sh
```

The script configures a Release shared-library build with CMake and installs it under `C99/out/macos26/install`.
