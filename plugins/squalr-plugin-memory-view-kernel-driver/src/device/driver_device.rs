use crate::device::DriverDeviceError;
use crate::protocol::{DriverMemoryRegion, DriverPingResponse};
use std::sync::Arc;

pub type SharedDriverDevice = Arc<dyn DriverDevice>;

/// One open connection to the kernel driver. Implementations must be safe to call from scan worker threads.
pub trait DriverDevice: Send + Sync {
    /// Exchanges protocol versions with the driver.
    fn ping(
        &self,
        client_version: u32,
    ) -> Result<DriverPingResponse, DriverDeviceError>;

    /// Reads up to `buffer.len()` bytes from the target process. Returns the number of bytes copied.
    fn read_memory(
        &self,
        process_id: u32,
        address: u64,
        buffer: &mut [u8],
    ) -> Result<u64, DriverDeviceError>;

    /// Writes up to `buffer.len()` bytes into the target process. Returns the number of bytes copied.
    fn write_memory(
        &self,
        process_id: u32,
        address: u64,
        buffer: &[u8],
    ) -> Result<u64, DriverDeviceError>;

    /// Queries the region containing `address` in the target process.
    fn query_memory(
        &self,
        process_id: u32,
        address: u64,
    ) -> Result<DriverMemoryRegion, DriverDeviceError>;
}
