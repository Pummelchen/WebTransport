# macOS 26 C++ Build Support

Primary output:

- Shared library: `CPP/out/macos26/install/lib/`
- Headers: `CPP/out/macos26/install/include/`
- CMake package files: `CPP/out/macos26/install/lib/cmake/`

Build command:

```sh
./CPP/platform/macos26/compile-dylib.sh
```

The script configures a Release shared-library build with CMake and installs it under `CPP/out/macos26/install`.
