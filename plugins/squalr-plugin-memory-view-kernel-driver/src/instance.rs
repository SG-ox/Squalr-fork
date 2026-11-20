use crate::constants::{KERNEL_DRIVER_PLUGIN_ID, WINDOWS_MAX_USERMODE_ADDRESS_32, WINDOWS_MAX_USERMODE_ADDRESS_64, WINDOWS_MIN_USERMODE_ADDRESS};
use crate::device::SharedDriverDevice;
use crate::protocol::SQUALR_MAX_TRANSFER_SIZE;
use crate::region_filter::{ProtectionSelection, RegionFilter, TypeSelection};
use squalr_engine_api::plugins::memory_view::{MemoryViewInstance, MemoryViewPluginError, PageRetrievalMode};
use squalr_engine_api::structures::memory::{bitness::Bitness, normalized_module::NormalizedModule, normalized_region::NormalizedRegion};
use squalr_engine_api::structures::processes::opened_process_info::OpenedProcessInfo;
use squalr_engine_targets_native::config::memory_settings_config::MemorySettingsConfig;
use squalr_engine_targets_native::memory_queryer::memory_queryer::MemoryQueryer;
use squalr_engine_targets_native::memory_queryer::memory_queryer_trait::MemoryQueryerTrait;
use std::collections::HashSet;

/// Serves one attached process through the kernel driver.
pub struct KernelDriverMemoryViewInstance {
    process_info: OpenedProcessInfo,
    device: SharedDriverDevice,
}

impl KernelDriverMemoryViewInstance {
    pub fn new(
        process_info: OpenedProcessInfo,
        device: SharedDriverDevice,
    ) -> Self {
        Self { process_info, device }
    }

    fn get_max_usermode_address(&self) -> u64 {
        match self.process_info.get_bitness() {
            Bitness::Bit32 => WINDOWS_MAX_USERMODE_ADDRESS_32,
            Bitness::Bit64 => WINDOWS_MAX_USERMODE_ADDRESS_64,
        }
    }

    /// Regions a full user-mode scan covers, matching the native `FromUserMode` query.
    fn build_usermode_filter(&self) -> RegionFilter {
        RegionFilter {
            required_protection: ProtectionSelection::default(),
            excluded_protection: ProtectionSelection::default(),
            allowed_types: TypeSelection {
                none: true,
                private: true,
                image: true,
                mapped: false,
            },
            start_address: 0,
            end_address: self.get_max_usermode_address(),
        }
    }

    /// Regions selected by the user's memory settings, matching the native `FromSettings` query.
    fn build_settings_filter(&self) -> RegionFilter {
        let max_usermode_address = self.get_max_usermode_address();
        let (start_address, end_address) = if MemorySettingsConfig::get_only_query_usermode() {
            (0, max_usermode_address)
        } else {
            (
                MemorySettingsConfig::get_start_address().min(max_usermode_address),
                MemorySettingsConfig::get_end_address().min(max_usermode_address),
            )
        };

        RegionFilter {
            required_protection: ProtectionSelection {
                write: MemorySettingsConfig::get_required_write(),
                execute: MemorySettingsConfig::get_required_execute(),
                copy_on_write: MemorySettingsConfig::get_required_copy_on_write(),
            },
            excluded_protection: ProtectionSelection {
                write: MemorySettingsConfig::get_excluded_write(),
                execute: MemorySettingsConfig::get_excluded_execute(),
                copy_on_write: MemorySettingsConfig::get_excluded_copy_on_write(),
            },
            allowed_types: TypeSelection {
                none: MemorySettingsConfig::get_memory_type_none(),
                private: MemorySettingsConfig::get_memory_type_private(),
                image: MemorySettingsConfig::get_memory_type_image(),
                mapped: MemorySettingsConfig::get_memory_type_mapped(),
            },
            start_address,
            end_address,
        }
    }

    fn collect_regions(
        &self,
        region_filter: &RegionFilter,
    ) -> Vec<NormalizedRegion> {
        let process_id = self.process_info.get_process_id();

        region_filter.collect_regions(|query_address| match self.device.query_memory(process_id, query_address) {
            Ok(region) => Some(region),
            Err(error) => {
                log::debug!("Kernel driver region query at {:#X} failed: {}", query_address, error);
                None
            }
        })
    }

    fn transfer_error(
        operation_name: &str,
        address: u64,
        message: impl std::fmt::Display,
    ) -> MemoryViewPluginError {
        MemoryViewPluginError::message(KERNEL_DRIVER_PLUGIN_ID, format!("{} at {:#X} failed: {}", operation_name, address, message))
    }
}

impl MemoryViewInstance for KernelDriverMemoryViewInstance {
    fn plugin_id(&self) -> &str {
        KERNEL_DRIVER_PLUGIN_ID
    }

    fn owns_address(
        &self,
        address: u64,
    ) -> bool {
        address >= WINDOWS_MIN_USERMODE_ADDRESS && address <= self.get_max_usermode_address()
    }

    fn get_virtual_pages(
        &self,
        page_retrieval_mode: PageRetrievalMode,
    ) -> Result<Vec<NormalizedRegion>, MemoryViewPluginError> {
        match page_retrieval_mode {
            PageRetrievalMode::FromSettings => Ok(self.collect_regions(&self.build_settings_filter())),
            PageRetrievalMode::FromUserMode => Ok(self.collect_regions(&self.build_usermode_filter())),
            PageRetrievalMode::FromNonModules => {
                let module_base_addresses: HashSet<u64> = MemoryQueryer::get_instance()
                    .get_modules(&self.process_info)
                    .iter()
                    .map(|module| module.get_base_address())
                    .collect();

                Ok(self
                    .collect_regions(&self.build_usermode_filter())
                    .into_iter()
                    .filter(|region| !module_base_addresses.contains(&region.get_base_address()))
                    .collect())
            }
            // Module listing is served by the native provider, so these modes fall back to it.
            PageRetrievalMode::FromModules | PageRetrievalMode::FromVirtualModules => Err(MemoryViewPluginError::unavailable(
                KERNEL_DRIVER_PLUGIN_ID,
                "module pages are served by the native provider",
            )),
        }
    }

    fn get_modules(&self) -> Result<Vec<NormalizedModule>, MemoryViewPluginError> {
        // The driver protocol has no module listing yet. The router merges this with the native module list.
        Ok(Vec::new())
    }

    fn read_bytes(
        &self,
        address: u64,
        values: &mut [u8],
    ) -> Result<(), MemoryViewPluginError> {
        let process_id = self.process_info.get_process_id();
        let mut chunk_address = address;

        for chunk in values.chunks_mut(SQUALR_MAX_TRANSFER_SIZE) {
            let bytes_read = self
                .device
                .read_memory(process_id, chunk_address, chunk)
                .map_err(|error| Self::transfer_error("Read", chunk_address, error))?;

            if bytes_read != chunk.len() as u64 {
                return Err(Self::transfer_error(
                    "Read",
                    chunk_address,
                    format!("copied {} of {} bytes", bytes_read, chunk.len()),
                ));
            }

            chunk_address = chunk_address.wrapping_add(chunk.len() as u64);
        }

        Ok(())
    }

    fn write_bytes(
        &self,
        address: u64,
        values: &[u8],
    ) -> Result<(), MemoryViewPluginError> {
        let process_id = self.process_info.get_process_id();
        let mut chunk_address = address;

        for chunk in values.chunks(SQUALR_MAX_TRANSFER_SIZE) {
            let bytes_written = self
                .device
                .write_memory(process_id, chunk_address, chunk)
                .map_err(|error| Self::transfer_error("Write", chunk_address, error))?;

            if bytes_written != chunk.len() as u64 {
                return Err(Self::transfer_error(
                    "Write",
                    chunk_address,
                    format!("copied {} of {} bytes", bytes_written, chunk.len()),
                ));
            }

            chunk_address = chunk_address.wrapping_add(chunk.len() as u64);
        }

        Ok(())
    }
}
