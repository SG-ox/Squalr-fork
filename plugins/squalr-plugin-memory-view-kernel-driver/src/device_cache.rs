use crate::device::{DriverDevice, DriverDeviceError, SharedDriverDevice};
use crate::protocol::SQUALR_DRIVER_PROTOCOL_VERSION;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type DriverDeviceOpener = Arc<dyn Fn() -> Result<SharedDriverDevice, DriverDeviceError> + Send + Sync>;

struct DeviceCacheState {
    device: Option<SharedDriverDevice>,
    last_probe_time: Option<Instant>,
    last_probe_error: Option<DriverDeviceError>,
}

/// Keeps one verified driver connection and re-checks it at a fixed interval.
/// `can_attach` runs on every routed memory operation, so the probe result must be cached.
pub struct DeviceCache {
    device_opener: DriverDeviceOpener,
    probe_interval: Duration,
    state: Mutex<DeviceCacheState>,
}

impl DeviceCache {
    pub fn new(
        device_opener: DriverDeviceOpener,
        probe_interval: Duration,
    ) -> Self {
        Self {
            device_opener,
            probe_interval,
            state: Mutex::new(DeviceCacheState {
                device: None,
                last_probe_time: None,
                last_probe_error: None,
            }),
        }
    }

    /// Returns the verified driver connection, or `None` when the driver is not available.
    pub fn get_device(&self) -> Option<SharedDriverDevice> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                log::error!("Failed to lock the kernel driver device cache: {}", error);
                return None;
            }
        };

        let is_probe_fresh = state
            .last_probe_time
            .map(|last_probe_time| last_probe_time.elapsed() < self.probe_interval)
            .unwrap_or(false);

        if is_probe_fresh {
            return state.device.clone();
        }

        let was_connected = state.device.is_some();
        let probe_result = match state.device.take() {
            Some(existing_device) => match verify_protocol_version(existing_device.as_ref()) {
                Ok(()) => Ok(existing_device),
                Err(_) => self.open_and_verify(),
            },
            None => self.open_and_verify(),
        };

        state.last_probe_time = Some(Instant::now());

        match probe_result {
            Ok(device) => {
                if !was_connected {
                    log::info!("Connected to the Squalr kernel driver.");
                }

                state.last_probe_error = None;

                state.device = Some(device.clone());
                Some(device)
            }
            Err(error) => {
                // Only log when the reason changes, so a missing driver does not flood the output.
                if state.last_probe_error.as_ref() != Some(&error) {
                    log::info!("Squalr kernel driver unavailable: {}.", error);
                }

                state.last_probe_error = Some(error);
                None
            }
        }
    }

    fn open_and_verify(&self) -> Result<SharedDriverDevice, DriverDeviceError> {
        let device = (self.device_opener)()?;

        verify_protocol_version(device.as_ref())?;

        Ok(device)
    }
}

/// Confirms the driver answers and speaks the same protocol version as this plugin.
pub fn verify_protocol_version(device: &dyn DriverDevice) -> Result<(), DriverDeviceError> {
    let ping_response = device.ping(SQUALR_DRIVER_PROTOCOL_VERSION)?;

    if ping_response.driver_version != SQUALR_DRIVER_PROTOCOL_VERSION {
        return Err(DriverDeviceError::ProtocolVersionMismatch {
            client_version: SQUALR_DRIVER_PROTOCOL_VERSION,
            driver_version: ping_response.driver_version,
        });
    }

    Ok(())
}
