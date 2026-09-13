# Cross-compile for 64-bit Windows with mingw-w64 (WT-134).
#
# This exists so that "the Windows port" is a build that can be RUN here rather than a paragraph: with a mingw
# toolchain and Windows OpenSSL, `scripts/check-windows-build.sh` configures the whole tree with this file and
# links every test and app into a PE32+ executable.
#
# `WT_WINDOWS_OPENSSL` is the prefix of a Windows OpenSSL (headers, import libraries and its CMake package).
# The MSYS2 build is what the script downloads:
#
#   https://repo.msys2.org/mingw/mingw64/mingw-w64-x86_64-openssl-<version>-any.pkg.tar.zst
#
# The system name is what makes CMake look for Windows things, and the three `ONLY` modes below are what keep it
# from finding the HOST's OpenSSL and linking a Mach-O library into a PE image.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

if(DEFINED WT_WINDOWS_OPENSSL)
  set(CMAKE_FIND_ROOT_PATH "${WT_WINDOWS_OPENSSL}")
  set(OPENSSL_ROOT_DIR "${WT_WINDOWS_OPENSSL}")
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
