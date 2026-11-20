use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DriverDeviceError {
    #[error("the kernel driver is only supported on Windows")]
    Unsupported,
    #[error("failed to open the kernel driver device `{device_path}` (Win32 error {error_code})")]
    OpenFailed { device_path: String, error_code: u32 },
    #[error("driver request {ioctl_code:#010X} failed (Win32 error {error_code})")]
    RequestFailed { ioctl_code: u32, error_code: u32 },
    #[error("driver request {ioctl_code:#010X} returned {returned_size} bytes, expected {expected_size}")]
    UnexpectedResponseSize { ioctl_code: u32, returned_size: u32, expected_size: u32 },
    #[error("driver protocol version {driver_version} does not match plugin protocol version {client_version}")]
    ProtocolVersionMismatch { client_version: u32, driver_version: u32 },
}
