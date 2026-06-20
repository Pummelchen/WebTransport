# C99 Platform Build Support

This folder contains OS-specific build entrypoints for the future C99 WebTransport library.

Supported target folders:

- `macos26/`
- `debian/`
- `freebsd/`
- `windows11/`

The scripts are thin wrappers around CMake. They standardize output locations under `C99/out/<platform>/` and fail fast until the C99 CMake project exists.

Generated build files and packaged libraries belong under `C99/out/`, not in source folders.
