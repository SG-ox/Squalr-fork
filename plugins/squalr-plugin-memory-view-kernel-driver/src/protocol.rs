//! Rust mirror of `driver/squalr_driver_protocol.h`. Layouts are checked at compile time.

// The IOCTL codes are only sent by the Windows device, but stay compiled everywhere so the layout tests run in CI.
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use std::mem::{offset_of, size_of};

/// Protocol version this plugin speaks. Must equal `SQUALR_DRIVER_PROTOCOL_VERSION` in the driver header.
pub const SQUALR_DRIVER_PROTOCOL_VERSION: u32 = 1;

/// Largest transfer issued in one read or write request. Must equal `SQUALR_MAX_TRANSFER_SIZE` in the driver header.
pub const SQUALR_MAX_TRANSFER_SIZE: usize = 4 * 1024 * 1024;

pub const FILE_DEVICE_SQUALR: u32 = 0x8000;

const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;
const FILE_READ_ACCESS: u32 = 1;
const FILE_WRITE_ACCESS: u32 = 2;

/// Equivalent of the Windows `CTL_CODE` macro.
pub const fn ctl_code(
    device_type: u32,
    function_code: u32,
    method: u32,
    access: u32,
) -> u32 {
    (device_type << 16) | (access << 14) | (function_code << 2) | method
}

pub const IOCTL_SQUALR_PING: u32 = ctl_code(FILE_DEVICE_SQUALR, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_SQUALR_READ_MEMORY: u32 = ctl_code(FILE_DEVICE_SQUALR, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS);
pub const IOCTL_SQUALR_WRITE_MEMORY: u32 = ctl_code(FILE_DEVICE_SQUALR, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);
pub const IOCTL_SQUALR_QUERY_MEMORY: u32 = ctl_code(FILE_DEVICE_SQUALR, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS);

/// Mirrors `SQUALR_PING_REQUEST`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SqualrPingRequest {
    pub client_version: u32,
    pub driver_version: u32,
    pub status_flags: u32,
    pub reserved: u32,
}

/// Mirrors `SQUALR_MEMORY_IO_REQUEST`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SqualrMemoryIoRequest {
    pub process_id: u32,
    pub reserved: u32,
    pub target_address: u64,
    pub user_buffer: u64,
    pub size: u64,
    pub bytes_transferred: u64,
}

/// Mirrors `SQUALR_QUERY_MEMORY_REQUEST`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SqualrQueryMemoryRequest {
    pub process_id: u32,
    pub reserved1: u32,
    pub query_address: u64,
    pub base_address: u64,
    pub allocation_base: u64,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub region_type: u32,
    pub reserved2: u32,
}

const _: () = assert!(size_of::<SqualrPingRequest>() == 16);
const _: () = assert!(size_of::<SqualrMemoryIoRequest>() == 40);
const _: () = assert!(size_of::<SqualrQueryMemoryRequest>() == 56);
const _: () = assert!(offset_of!(SqualrMemoryIoRequest, target_address) == 0x08);
const _: () = assert!(offset_of!(SqualrMemoryIoRequest, bytes_transferred) == 0x20);
const _: () = assert!(offset_of!(SqualrQueryMemoryRequest, query_address) == 0x08);
const _: () = assert!(offset_of!(SqualrQueryMemoryRequest, state) == 0x28);

/// Region information returned by the driver for one query.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DriverMemoryRegion {
    pub base_address: u64,
    pub allocation_base: u64,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub region_type: u32,
}

impl From<&SqualrQueryMemoryRequest> for DriverMemoryRegion {
    fn from(query_request: &SqualrQueryMemoryRequest) -> Self {
        Self {
            base_address: query_request.base_address,
            allocation_base: query_request.allocation_base,
            region_size: query_request.region_size,
            state: query_request.state,
            protect: query_request.protect,
            region_type: query_request.region_type,
        }
    }
}

/// Driver identity returned by a successful ping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverPingResponse {
    pub driver_version: u32,
    pub status_flags: u32,
}
