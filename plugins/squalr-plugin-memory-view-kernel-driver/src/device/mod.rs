mod driver_device;
mod driver_device_error;

#[cfg(target_os = "windows")]
mod windows_driver_device;

pub use driver_device::{DriverDevice, SharedDriverDevice};
pub use driver_device_error::DriverDeviceError;

/// Opens the platform driver device. Only Windows has a driver, every other platform reports it as unsupported.
pub fn open_platform_driver_device() -> Result<SharedDriverDevice, DriverDeviceError> {
    #[cfg(target_os = "windows")]
    {
        windows_driver_device::WindowsDriverDevice::open(crate::constants::KERNEL_DRIVER_DEVICE_PATH)
            .map(|device| std::sync::Arc::new(device) as SharedDriverDevice)
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(DriverDeviceError::Unsupported)
    }
}
