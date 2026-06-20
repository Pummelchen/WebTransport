# C++ Build Output Root

Platform build scripts write generated files here.

Expected layout after builds:

```text
out/
  macos26/
    build/
    install/
    package/
  debian/
    build/
    install/
    package/
  freebsd/
    build/
    install/
    package/
  windows11/
    build/
    install/
    package/
```

Generated binaries, object files, CMake cache files, packages, and checksums are intentionally ignored by git. Only this README and `.gitignore` are tracked.
