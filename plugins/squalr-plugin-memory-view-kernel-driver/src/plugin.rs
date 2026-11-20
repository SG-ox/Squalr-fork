use crate::constants::{DRIVER_PROBE_INTERVAL_MILLISECONDS, KERNEL_DRIVER_PLUGIN_DESCRIPTION, KERNEL_DRIVER_PLUGIN_DISPLAY_NAME, KERNEL_DRIVER_PLUGIN_ID};
use crate::device::open_platform_driver_device;
use crate::device_cache::{DeviceCache, DriverDeviceOpener};
use crate::instance::KernelDriverMemoryViewInstance;
use squalr_engine_api::{
    plugins::memory_view::{MemoryViewInstance, MemoryViewPlugin, MemoryViewPluginError},
    plugins::{Plugin, PluginCapability, PluginMetadata, PluginPackage, PluginPermission},
    structures::processes::opened_process_info::OpenedProcessInfo,
};
use std::sync::Arc;
use std::time::Duration;

/// Memory view that reads, writes, and maps process memory through the Squalr kernel driver.
/// Disabled by default. When enabled and the driver is running, it serves every attached process.
pub struct KernelDriverMemoryViewPlugin {
    metadata: PluginMetadata,
    device_cache: DeviceCache,
}

impl KernelDriverMemoryViewPlugin {
    pub fn new() -> Self {
        Self::with_device_opener(Arc::new(open_platform_driver_device))
    }

    /// Builds the plugin with a custom way of opening the driver. Used by tests to supply a fake driver.
    pub fn with_device_opener(device_opener: DriverDeviceOpener) -> Self {
        Self {
            metadata: PluginMetadata::new_with_permissions(
                KERNEL_DRIVER_PLUGIN_ID,
                KERNEL_DRIVER_PLUGIN_DISPLAY_NAME,
                KERNEL_DRIVER_PLUGIN_DESCRIPTION,
                vec![PluginCapability::MemoryView],
                vec![
                    PluginPermission::ReadProcessMemory,
                    PluginPermission::WriteProcessMemory,
                ],
                true,
                false,
            ),
            device_cache: DeviceCache::new(device_opener, Duration::from_millis(DRIVER_PROBE_INTERVAL_MILLISECONDS)),
        }
    }
}

impl Default for KernelDriverMemoryViewPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for KernelDriverMemoryViewPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
}

impl PluginPackage for KernelDriverMemoryViewPlugin {
    fn as_memory_view_plugin(&self) -> Option<&dyn MemoryViewPlugin> {
        Some(self)
    }
}

impl MemoryViewPlugin for KernelDriverMemoryViewPlugin {
    fn can_attach(
        &self,
        _process_info: &OpenedProcessInfo,
    ) -> bool {
        self.device_cache.get_device().is_some()
    }

    fn create_instance(
        &self,
        process_info: &OpenedProcessInfo,
    ) -> Result<Box<dyn MemoryViewInstance>, MemoryViewPluginError> {
        let device = self
            .device_cache
            .get_device()
            .ok_or_else(|| MemoryViewPluginError::unavailable(KERNEL_DRIVER_PLUGIN_ID, "the Squalr kernel driver is not running"))?;

        Ok(Box::new(KernelDriverMemoryViewInstance::new(process_info.clone(), device)))
    }
}
