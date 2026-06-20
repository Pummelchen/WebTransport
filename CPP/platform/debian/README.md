# Debian C++ Build Support

Primary output:

- Shared library: `CPP/out/debian/install/lib/`
- Headers: `CPP/out/debian/install/include/`
- CMake package files: `CPP/out/debian/install/lib/cmake/`

Build command:

```sh
./CPP/platform/debian/compile-so.sh
```

The script configures a Release shared-library build with CMake and installs it under `CPP/out/debian/install`.
