# DLLMemLdr

## Overview

DLLMemLdr is a lightweight C library that loads DLLs entirely from memory, eliminating the need for disk storage. It utilizes wrapped NtAPI functions along with custom implementations of `GetProcAddress` and `GetModuleHandle`. The library is designed for easy integration and a minimal footprint.

## Features

- **In-Memory DLL Loading**: Load DLLs directly from memory without writing to disk.
- **Wrapped NtAPI Functions**: Utilizes custom implementations for allocating memory to avoid userland hooking.
- **Custom GetProcAddress and GetModuleHandle**.
- **Easy Implementation**: Simply copy `DLLMemLdr.c` and `DLLMemLdr.h` into your project.


## Getting Started

### Prerequisites

- C/C++ compiler (GCC, Clang, or MSVC)
- CMake for building the project

### Installation

1. **Copy the Files**:
   - Copy `DLLMemLdr.c` and `DLLMemLdr.h` into your project directory.

2. **Include the Header**:
   In your source files, include the library header:
   `#include "DLLMemLdr.h"`