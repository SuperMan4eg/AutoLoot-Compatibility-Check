# Building AutoLoot Compatibility Check

## Requirements

- Windows 10 or Windows 11, 64-bit
- CMake 3.20 or newer
- MinGW-w64 GCC with C++20 support

The published diagnostic is built with GCC 15.2.0 using the MinGW Makefiles
generator. It links only to Windows system libraries: `bcrypt.dll`,
`KERNEL32.dll`, and `msvcrt.dll`.

## Build

Open a terminal in this source directory and run:

```powershell
cmake -S . -B build-v9 -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build-v9 --config Release
```

The resulting file is:

```text
build-v9/AutoLootCompatibilityCheck.exe
```

The CMake configuration statically links the GCC and C++ runtime. A binary built
with another compiler version may have a different SHA-256 hash even when built
from identical source.
## Local verification

Place the checker next to `ACOdyssey.exe` and/or `ACOdyssey_plus.exe`, run it,
and confirm that `AutoLootCompatibilityReport.txt` contains:

```text
tool_version=9
scan_count=...
result=report_complete
```

When both executable names are present, verify that the report contains both
`scan.0.*` and `scan.1.*` namespaces plus matching `summary.*` blocks.

Hash every tested game executable before and after the run to independently
confirm that it was not changed. The checker opens executable files for reading
only.

For an explicit single-file or multi-file test, pass one or more paths on the
command line. Explicit arguments disable automatic filename discovery for that
run.
