# FreeBSD C++ Build Support

Primary output:

- Shared library: `CPP/out/freebsd/install/lib/`
- Headers: `CPP/out/freebsd/install/include/`
- CMake package files: `CPP/out/freebsd/install/lib/cmake/`

Build command:

```sh
./CPP/platform/freebsd/compile-so.sh
```

The script configures a Release shared-library build with CMake and installs it under `CPP/out/freebsd/install`.
