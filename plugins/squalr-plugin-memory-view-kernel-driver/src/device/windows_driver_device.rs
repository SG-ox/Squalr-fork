use crate::device::{DriverDevice, DriverDeviceError};
use crate::protocol::{
    DriverMemoryRegion, DriverPingResponse, IOCTL_SQUALR_PING, IOCTL_SQUALR_QUERY_MEMORY, IOCTL_SQUALR_READ_MEMORY, IOCTL_SQUALR_WRITE_MEMORY,
    SqualrMemoryIoRequest, SqualrPingRequest, SqualrQueryMemoryRequest,
};
use std::ffi::c_void;
use std::mem::size_of;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// A synchronous handle to the Squalr kernel driver device.
pub struct WindowsDriverDevice {
    device_handle: HANDLE,
}

// The handle is only used with synchronous DeviceIoControl calls, which Windows allows from any thread.
unsafe impl Send for WindowsDriverDevice {}
unsafe impl Sync for WindowsDriverDevice {}

impl WindowsDriverDevice {
    /// Opens the driver's symbolic link, for example `\\.\Squalr`.
    pub fn open(device_path: &str) -> Result<Self, DriverDeviceError> {
        let wide_device_path: Vec<u16> = device_path.encode_utf16().chain(std::iter::once(0)).collect();

        let device_handle = unsafe {
            CreateFileW(
                wide_device_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };

        if device_handle == INVALID_HANDLE_VALUE || device_handle.is_null() {
            return Err(DriverDeviceError::OpenFailed {
                device_path: device_path.to_string(),
                error_code: unsafe { GetLastError() },
            });
        }

        Ok(Self { device_handle })
    }

    /// Sends one METHOD_BUFFERED request where the same struct is both input and output.
    fn send_request<RequestType>(
        &self,
        ioctl_code: u32,
        request: &mut RequestType,
    ) -> Result<(), DriverDeviceError> {
        let request_size = size_of::<RequestType>() as u32;
        let request_pointer = request as *mut RequestType as *mut c_void;
        let mut returned_size: u32 = 0;

        let succeeded = unsafe {
            DeviceIoControl(
                self.device_handle,
                ioctl_code,
                request_pointer as *const c_void,
                request_size,
                request_pointer,
                request_size,
                &mut returned_size,
                std::ptr::null_mut(),
            )
        };

        if succeeded == 0 {
            return Err(DriverDeviceError::RequestFailed {
                ioctl_code,
                error_code: unsafe { GetLastError() },
            });
        }

        if returned_size != request_size {
            return Err(DriverDeviceError::UnexpectedResponseSize {
                ioctl_code,
                returned_size,
                expected_size: request_size,
            });
        }

        Ok(())
    }

    fn transfer(
        &self,
        ioctl_code: u32,
        process_id: u32,
        address: u64,
        user_buffer: u64,
        size: usize,
    ) -> Result<u64, DriverDeviceError> {
        let mut io_request = SqualrMemoryIoRequest {
            process_id,
            target_address: address,
            user_buffer,
            size: size as u64,
            ..Default::default()
        };

        self.send_request(ioctl_code, &mut io_request)?;

        Ok(io_request.bytes_transferred)
    }
}

impl DriverDevice for WindowsDriverDevice {
    fn ping(
        &self,
        client_version: u32,
    ) -> Result<DriverPingResponse, DriverDeviceError> {
        let mut ping_request = SqualrPingRequest {
            client_version,
            ..Default::default()
        };

        self.send_request(IOCTL_SQUALR_PING, &mut ping_request)?;

        Ok(DriverPingResponse {
            driver_version: ping_request.driver_version,
            status_flags: ping_request.status_flags,
        })
    }

    fn read_memory(
        &self,
        process_id: u32,
        address: u64,
        buffer: &mut [u8],
    ) -> Result<u64, DriverDeviceError> {
        self.transfer(IOCTL_SQUALR_READ_MEMORY, process_id, address, buffer.as_mut_ptr() as u64, buffer.len())
    }

    fn write_memory(
        &self,
        process_id: u32,
        address: u64,
        buffer: &[u8],
    ) -> Result<u64, DriverDeviceError> {
        self.transfer(IOCTL_SQUALR_WRITE_MEMORY, process_id, address, buffer.as_ptr() as u64, buffer.len())
    }

    fn query_memory(
        &self,
        process_id: u32,
        address: u64,
    ) -> Result<DriverMemoryRegion, DriverDeviceError> {
        let mut query_request = SqualrQueryMemoryRequest {
            process_id,
            query_address: address,
            ..Default::default()
        };

        self.send_request(IOCTL_SQUALR_QUERY_MEMORY, &mut query_request)?;

        Ok(DriverMemoryRegion::from(&query_request))
    }
}

impl Drop for WindowsDriverDevice {
    fn drop(&mut self) {
        if unsafe { CloseHandle(self.device_handle) } == 0 {
            log::warn!("Failed to close the kernel driver device handle (Win32 error {}).", unsafe { GetLastError() });
        }
    }
}
