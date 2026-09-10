# Building AutoLoot Compatibility Check

## Requirements

- Windows 10 or Windows 11, 64-bit
- CMake 3.20 or newer
- MinGW-w64 GCC with C++20 support

The published diagnostic was built with GCC 15.2.0 using the MinGW Makefiles
generator. It links only to Windows system libraries: `bcrypt.dll`,
`KERNEL32.dll`, and `msvcrt.dll`.

## Build

Open a terminal in this source directory and run:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

The resulting file is:

```text
build/AutoLootCompatibilityCheck.exe
```

The CMake configuration statically links the GCC and C++ runtime. A binary built
with another compiler version may have a different SHA-256 hash even when built
from identical source.

## Local verification

Place a test copy of the checker next to `ACOdyssey.exe`, run it, and confirm
that `AutoLootCompatibilityReport.txt` ends with:

```text
result=report_complete
```

Hash `ACOdyssey.exe` before and after the run to independently confirm that it
was not changed. The checker opens the game executable for reading only.

