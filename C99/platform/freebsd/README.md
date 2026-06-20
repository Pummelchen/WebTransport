# FreeBSD C99 Build Support

Primary output:

- Shared library: `C99/out/freebsd/install/lib/`
- Static library: `C99/out/freebsd/install/lib/`
- Headers: `C99/out/freebsd/install/include/`
- CMake package files: `C99/out/freebsd/install/lib/cmake/`

Build command:

```sh
./C99/platform/freebsd/compile-so.sh
```

The script configures a Release shared-library build with CMake and installs it under `C99/out/freebsd/install`.
