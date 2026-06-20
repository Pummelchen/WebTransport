# C++ Platform Build Support

This folder contains OS-specific build entrypoints for the future C++23 WebTransport library.

Supported target folders:

- `macos26/`
- `debian/`
- `freebsd/`
- `windows11/`

The scripts are intentionally thin wrappers around CMake. They standardize output locations under `CPP/out/<platform>/` and fail fast until the C++ CMake project exists.

Generated build files and packaged libraries belong under `CPP/out/`, not in source folders.
