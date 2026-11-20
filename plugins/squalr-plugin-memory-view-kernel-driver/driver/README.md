# Squalr kernel driver protocol

`squalr_driver_protocol.h` is the contract between the Squalr kernel driver and the
`squalr-plugin-memory-view-kernel-driver` plugin. The Rust mirror lives in `src/protocol.rs`,
and both files assert the same struct sizes and offsets.

## How the plugin uses the driver

1. Opens `\\.\Squalr` with `GENERIC_READ | GENERIC_WRITE`.
2. Sends `IOCTL_SQUALR_PING` with `ClientVersion = SQUALR_DRIVER_PROTOCOL_VERSION`. The driver must
   write its own version to `DriverVersion`. The plugin only attaches when both versions match.
3. Walks the address space with `IOCTL_SQUALR_QUERY_MEMORY`, advancing by `BaseAddress + RegionSize`.
4. Reads and writes with `IOCTL_SQUALR_READ_MEMORY` / `IOCTL_SQUALR_WRITE_MEMORY`, in chunks of at
   most `SQUALR_MAX_TRANSFER_SIZE` bytes. A transfer counts as failed unless `BytesTransferred == Size`.

Every request is `METHOD_BUFFERED`, and the same struct is both input and output. The driver must
set `Irp->IoStatus.Information = sizeof(request)` on success, or the plugin rejects the response.

## Requirements for the driver

- **Lock down the device.** Create it with `IoCreateDeviceSecure` and `SQUALR_DEVICE_SDDL`
  (SYSTEM and Administrators only). An open device lets any local user read and write every
  process, which turns the driver into a privilege escalation tool.
- **Never trust `UserBuffer`.** It is a raw user-mode pointer inside a buffered request. Copy with
  `MmCopyVirtualMemory` using `UserMode` as the previous mode for the caller side, or wrap access in
  `__try` with `ProbeForRead` / `ProbeForWrite`. Dereferencing it directly lets a caller pass a
  kernel address and overwrite kernel memory.
- **Validate input sizes.** Check `InputBufferLength` and `OutputBufferLength` against
  `sizeof(request)` before touching `Irp->AssociatedIrp.SystemBuffer`, and reject `Size` values
  larger than `SQUALR_MAX_TRANSFER_SIZE` or zero.
- **Release process references.** Every `PsLookupProcessByProcessId` needs a matching
  `ObDereferenceObject`, including on error paths.
- **Query with an attached or opened process.** `ZwQueryVirtualMemory` needs a handle to the target
  (for example `ObOpenObjectByPointer` with `OBJ_KERNEL_HANDLE`), closed with `ZwClose` afterwards.

## Installing for development

Unsigned drivers only load with test signing enabled (`bcdedit /set testsigning on`, then reboot).
Use a VM for development. A driver bug causes a blue screen, not an application crash.
