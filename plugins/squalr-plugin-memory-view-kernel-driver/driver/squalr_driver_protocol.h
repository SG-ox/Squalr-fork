#pragma once

// Shared contract between the Squalr kernel driver and the Squalr memory-view plugin.
// Any change here must be mirrored in `src/protocol.rs`, and SQUALR_DRIVER_PROTOCOL_VERSION must be bumped.

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

// Bump whenever a request layout or IOCTL meaning changes. The plugin refuses to attach on mismatch.
#define SQUALR_DRIVER_PROTOCOL_VERSION 1u

// Device object and the symbolic link user mode opens with CreateFileW(L"\\\\.\\Squalr", ...).
#define SQUALR_DEVICE_NAME L"\\Device\\Squalr"
#define SQUALR_SYMBOLIC_LINK_NAME L"\\DosDevices\\Squalr"

// Restrict the device to SYSTEM and Administrators. Pass this to IoCreateDeviceSecure.
// Without it, any unprivileged user can read and write every process on the machine.
#define SQUALR_DEVICE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// Custom device type in the 3rd-party range (0x8000 - 0xFFFF).
#define FILE_DEVICE_SQUALR 0x8000

// IOCTL function codes (0x800 - 0xFFF are reserved for vendor/custom use).
#define IOCTL_SQUALR_PING \
    CTL_CODE(FILE_DEVICE_SQUALR, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SQUALR_READ_MEMORY \
    CTL_CODE(FILE_DEVICE_SQUALR, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_SQUALR_WRITE_MEMORY \
    CTL_CODE(FILE_DEVICE_SQUALR, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_SQUALR_QUERY_MEMORY \
    CTL_CODE(FILE_DEVICE_SQUALR, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)

// Largest transfer the plugin issues in one read or write request. The driver should reject anything larger.
#define SQUALR_MAX_TRANSFER_SIZE (4ull * 1024ull * 1024ull)

#pragma pack(push, 8)

// 16 bytes. Input: ClientVersion. Output: DriverVersion, StatusFlags.
typedef struct _SQUALR_PING_REQUEST {
    UINT32 ClientVersion;
    UINT32 DriverVersion;
    UINT32 StatusFlags;
    UINT32 Reserved;
} SQUALR_PING_REQUEST, *PSQUALR_PING_REQUEST;

// 40 bytes. Used for both Read and Write requests.
// UserBuffer is an embedded user-mode pointer. The driver MUST NOT dereference it directly.
// Copy with MmCopyVirtualMemory(..., UserMode, ...) or probe it with ProbeForRead/ProbeForWrite inside __try.
typedef struct _SQUALR_MEMORY_IO_REQUEST {
    UINT32 ProcessId;         // Target process PID.
    UINT32 Reserved;          // Explicit padding so TargetAddress starts at offset +0x08.
    UINT64 TargetAddress;     // 64-bit virtual address in target process.
    UINT64 UserBuffer;        // 64-bit pointer to caller's user-mode buffer.
    UINT64 Size;              // Requested byte count. Must be <= SQUALR_MAX_TRANSFER_SIZE.
    UINT64 BytesTransferred;  // Output: actual bytes copied.
} SQUALR_MEMORY_IO_REQUEST, *PSQUALR_MEMORY_IO_REQUEST;

// 56 bytes. Mirrors the MEMORY_BASIC_INFORMATION fields needed by Squalr's region mapper.
typedef struct _SQUALR_QUERY_MEMORY_REQUEST {
    UINT32 ProcessId;         // Target process PID.
    UINT32 Reserved1;         // Explicit padding so QueryAddress starts at offset +0x08.
    UINT64 QueryAddress;      // Input: virtual address to query.
    UINT64 BaseAddress;       // Output: base address of region.
    UINT64 AllocationBase;    // Output: base address of allocation.
    UINT64 RegionSize;        // Output: size of region in bytes.
    UINT32 State;             // Output: MEM_COMMIT, MEM_FREE, MEM_RESERVE.
    UINT32 Protect;           // Output: PAGE_READWRITE, PAGE_EXECUTE_READ, etc.
    UINT32 Type;              // Output: MEM_PRIVATE, MEM_IMAGE, MEM_MAPPED.
    UINT32 Reserved2;         // Explicit trailing padding to keep total size a multiple of 8.
} SQUALR_QUERY_MEMORY_REQUEST, *PSQUALR_QUERY_MEMORY_REQUEST;

#pragma pack(pop)

// Compile-time layout checks. These match the assertions in `src/protocol.rs`.
C_ASSERT(sizeof(SQUALR_PING_REQUEST) == 16);
C_ASSERT(sizeof(SQUALR_MEMORY_IO_REQUEST) == 40);
C_ASSERT(sizeof(SQUALR_QUERY_MEMORY_REQUEST) == 56);
C_ASSERT(FIELD_OFFSET(SQUALR_MEMORY_IO_REQUEST, TargetAddress) == 0x08);
C_ASSERT(FIELD_OFFSET(SQUALR_MEMORY_IO_REQUEST, BytesTransferred) == 0x20);
C_ASSERT(FIELD_OFFSET(SQUALR_QUERY_MEMORY_REQUEST, QueryAddress) == 0x08);
C_ASSERT(FIELD_OFFSET(SQUALR_QUERY_MEMORY_REQUEST, State) == 0x28);
