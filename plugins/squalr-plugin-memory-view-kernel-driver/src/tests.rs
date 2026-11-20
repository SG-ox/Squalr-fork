use crate::KernelDriverMemoryViewPlugin;
use crate::device::{DriverDevice, DriverDeviceError, SharedDriverDevice};
use crate::device_cache::{DeviceCache, DriverDeviceOpener};
use crate::instance::KernelDriverMemoryViewInstance;
use crate::protocol::{
    DriverMemoryRegion, DriverPingResponse, IOCTL_SQUALR_PING, IOCTL_SQUALR_QUERY_MEMORY, IOCTL_SQUALR_READ_MEMORY, IOCTL_SQUALR_WRITE_MEMORY,
    SQUALR_DRIVER_PROTOCOL_VERSION, SQUALR_MAX_TRANSFER_SIZE,
};
use crate::region_filter::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_READWRITE, ProtectionSelection, RegionFilter, TypeSelection,
};
use squalr_engine_api::plugins::Plugin;
use squalr_engine_api::plugins::memory_view::{MemoryViewInstance, MemoryViewPlugin};
use squalr_engine_api::structures::memory::bitness::Bitness;
use squalr_engine_api::structures::processes::opened_process_info::OpenedProcessInfo;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const FAKE_PROCESS_ID: u32 = 1234;

/// In-memory stand-in for the kernel driver.
struct FakeDriverDevice {
    driver_version: u32,
    regions: Vec<DriverMemoryRegion>,
    memory_base_address: u64,
    memory: Mutex<Vec<u8>>,
    /// When set, reads report this many bytes copied instead of the full request.
    forced_bytes_transferred: Option<u64>,
    transfer_sizes: Mutex<Vec<usize>>,
    ping_count: AtomicUsize,
}

impl FakeDriverDevice {
    fn new(driver_version: u32) -> Self {
        Self {
            driver_version,
            regions: Vec::new(),
            memory_base_address: 0x10000,
            memory: Mutex::new(vec![0u8; 0x1000]),
            forced_bytes_transferred: None,
            transfer_sizes: Mutex::new(Vec::new()),
            ping_count: AtomicUsize::new(0),
        }
    }

    fn memory_range(
        &self,
        process_id: u32,
        address: u64,
        length: usize,
    ) -> Result<std::ops::Range<usize>, DriverDeviceError> {
        let memory_length = self.memory.lock().map(|memory| memory.len()).unwrap_or(0);
        let start_offset = address
            .checked_sub(self.memory_base_address)
            .map(|offset| offset as usize);

        match start_offset {
            Some(start_offset) if process_id == FAKE_PROCESS_ID && start_offset + length <= memory_length => Ok(start_offset..start_offset + length),
            _ => Err(DriverDeviceError::RequestFailed {
                ioctl_code: IOCTL_SQUALR_READ_MEMORY,
                error_code: 299,
            }),
        }
    }
}

impl DriverDevice for FakeDriverDevice {
    fn ping(
        &self,
        _client_version: u32,
    ) -> Result<DriverPingResponse, DriverDeviceError> {
        self.ping_count.fetch_add(1, Ordering::SeqCst);

        Ok(DriverPingResponse {
            driver_version: self.driver_version,
            status_flags: 0,
        })
    }

    fn read_memory(
        &self,
        process_id: u32,
        address: u64,
        buffer: &mut [u8],
    ) -> Result<u64, DriverDeviceError> {
        if let Ok(mut transfer_sizes) = self.transfer_sizes.lock() {
            transfer_sizes.push(buffer.len());
        }

        if let Some(forced_bytes_transferred) = self.forced_bytes_transferred {
            return Ok(forced_bytes_transferred);
        }

        let memory_range = self.memory_range(process_id, address, buffer.len())?;
        let memory = self.memory.lock().map_err(|_| DriverDeviceError::Unsupported)?;
        buffer.copy_from_slice(&memory[memory_range]);

        Ok(buffer.len() as u64)
    }

    fn write_memory(
        &self,
        process_id: u32,
        address: u64,
        buffer: &[u8],
    ) -> Result<u64, DriverDeviceError> {
        let memory_range = self.memory_range(process_id, address, buffer.len())?;
        let mut memory = self.memory.lock().map_err(|_| DriverDeviceError::Unsupported)?;
        memory[memory_range].copy_from_slice(buffer);

        Ok(buffer.len() as u64)
    }

    fn query_memory(
        &self,
        _process_id: u32,
        address: u64,
    ) -> Result<DriverMemoryRegion, DriverDeviceError> {
        self.regions
            .iter()
            .find(|region| address >= region.base_address && address < region.base_address + region.region_size)
            .copied()
            .ok_or(DriverDeviceError::RequestFailed {
                ioctl_code: IOCTL_SQUALR_QUERY_MEMORY,
                error_code: 87,
            })
    }
}

fn region(
    base_address: u64,
    region_size: u64,
    state: u32,
    protect: u32,
    region_type: u32,
) -> DriverMemoryRegion {
    DriverMemoryRegion {
        base_address,
        allocation_base: base_address,
        region_size,
        state,
        protect,
        region_type,
    }
}

fn permissive_filter(end_address: u64) -> RegionFilter {
    RegionFilter {
        required_protection: ProtectionSelection::default(),
        excluded_protection: ProtectionSelection::default(),
        allowed_types: TypeSelection {
            none: true,
            private: true,
            image: true,
            mapped: true,
        },
        start_address: 0,
        end_address,
    }
}

fn fake_process() -> OpenedProcessInfo {
    OpenedProcessInfo::new(FAKE_PROCESS_ID, "target.exe".to_string(), 0, Bitness::Bit64, None)
}

fn opener_for(device: Arc<FakeDriverDevice>) -> DriverDeviceOpener {
    Arc::new(move || Ok(device.clone() as SharedDriverDevice))
}

#[test]
fn ioctl_codes_match_ctl_code_macro_output() {
    // Values produced by CTL_CODE in the driver header.
    assert_eq!(IOCTL_SQUALR_PING, 0x8000_2000);
    assert_eq!(IOCTL_SQUALR_READ_MEMORY, 0x8000_6004);
    assert_eq!(IOCTL_SQUALR_WRITE_MEMORY, 0x8000_A008);
    assert_eq!(IOCTL_SQUALR_QUERY_MEMORY, 0x8000_600C);
}

#[test]
fn filter_rejects_uncommitted_guard_and_disallowed_type_regions() {
    let filter = RegionFilter {
        allowed_types: TypeSelection {
            none: false,
            private: true,
            image: true,
            mapped: false,
        },
        ..permissive_filter(u64::MAX)
    };

    assert!(filter.accepts(&region(0x10000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE)));
    assert!(!filter.accepts(&region(0x10000, 0x1000, 0x2000, PAGE_READWRITE, MEM_PRIVATE)));
    assert!(!filter.accepts(&region(0x10000, 0x1000, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD, MEM_PRIVATE)));
    assert!(!filter.accepts(&region(0x10000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_MAPPED)));
}

#[test]
fn filter_applies_required_and_excluded_protection() {
    let writable_only = RegionFilter {
        required_protection: ProtectionSelection {
            write: true,
            ..Default::default()
        },
        ..permissive_filter(u64::MAX)
    };
    let no_execute = RegionFilter {
        excluded_protection: ProtectionSelection {
            execute: true,
            ..Default::default()
        },
        ..permissive_filter(u64::MAX)
    };

    assert!(writable_only.accepts(&region(0x10000, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE)));
    assert!(!writable_only.accepts(&region(0x10000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_IMAGE)));
    assert!(!no_execute.accepts(&region(0x10000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_IMAGE)));
}

#[test]
fn region_walk_collects_accepted_regions_and_stops_when_queries_fail() {
    let regions = vec![
        region(0x0, 0x10000, 0x10000, 0x01, 0),
        region(0x10000, 0x2000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        region(0x12000, 0x1000, 0x2000, PAGE_READWRITE, MEM_PRIVATE),
        region(0x13000, 0x3000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_IMAGE),
    ];
    let collected = permissive_filter(0x7FFF_FFFF_FFFF).collect_regions(|query_address| {
        regions
            .iter()
            .find(|region| query_address >= region.base_address && query_address < region.base_address + region.region_size)
            .copied()
    });

    let collected_bounds: Vec<(u64, u64)> = collected
        .iter()
        .map(|region| (region.get_base_address(), region.get_region_size()))
        .collect();

    assert_eq!(collected_bounds, vec![(0x10000, 0x2000), (0x13000, 0x3000)]);
}

#[test]
fn region_walk_stops_when_driver_returns_a_non_advancing_region() {
    let query_count = AtomicUsize::new(0);
    let collected = permissive_filter(u64::MAX).collect_regions(|_query_address| {
        query_count.fetch_add(1, Ordering::SeqCst);
        Some(region(0, 0, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE))
    });

    assert!(collected.is_empty());
    assert_eq!(query_count.load(Ordering::SeqCst), 1);
}

#[test]
fn instance_reads_and_writes_through_the_driver() {
    let device = Arc::new(FakeDriverDevice::new(SQUALR_DRIVER_PROTOCOL_VERSION));
    let instance = KernelDriverMemoryViewInstance::new(fake_process(), device.clone());

    instance
        .write_bytes(0x10010, &[0xDE, 0xAD, 0xBE, 0xEF])
        .expect("Expected the fake driver write to succeed.");

    let mut read_back = [0u8; 4];
    instance
        .read_bytes(0x10010, &mut read_back)
        .expect("Expected the fake driver read to succeed.");

    assert_eq!(read_back, [0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn instance_rejects_partial_reads() {
    let mut device = FakeDriverDevice::new(SQUALR_DRIVER_PROTOCOL_VERSION);
    device.forced_bytes_transferred = Some(2);
    let instance = KernelDriverMemoryViewInstance::new(fake_process(), Arc::new(device));
    let mut values = [0u8; 4];

    assert!(instance.read_bytes(0x10000, &mut values).is_err());
}

#[test]
fn instance_splits_large_reads_into_bounded_transfers() {
    let device = FakeDriverDevice::new(SQUALR_DRIVER_PROTOCOL_VERSION);
    *device.memory.lock().expect("Expected the fake memory lock.") = vec![0u8; SQUALR_MAX_TRANSFER_SIZE * 2 + 16];
    let device = Arc::new(device);
    let instance = KernelDriverMemoryViewInstance::new(fake_process(), device.clone());
    let mut values = vec![0u8; SQUALR_MAX_TRANSFER_SIZE * 2 + 16];

    instance
        .read_bytes(0x10000, &mut values)
        .expect("Expected the chunked read to succeed.");

    let transfer_sizes = device
        .transfer_sizes
        .lock()
        .expect("Expected the transfer log lock.")
        .clone();

    assert_eq!(transfer_sizes, vec![SQUALR_MAX_TRANSFER_SIZE, SQUALR_MAX_TRANSFER_SIZE, 16]);
}

#[test]
fn instance_only_owns_usermode_addresses() {
    let device = Arc::new(FakeDriverDevice::new(SQUALR_DRIVER_PROTOCOL_VERSION));
    let instance = KernelDriverMemoryViewInstance::new(fake_process(), device);

    assert!(!instance.owns_address(0x1000));
    assert!(instance.owns_address(0x10000));
    assert!(instance.owns_address(0x7FFF_FFFF_FFFF));
    assert!(!instance.owns_address(0xFFFF_8000_0000_0000));
}

#[test]
fn plugin_is_built_in_and_disabled_by_default() {
    let plugin = KernelDriverMemoryViewPlugin::with_device_opener(Arc::new(|| Err(DriverDeviceError::Unsupported)));

    assert!(plugin.metadata().get_is_built_in());
    assert!(!plugin.metadata().get_is_enabled_by_default());
}

#[test]
fn plugin_does_not_attach_without_a_driver() {
    let plugin = KernelDriverMemoryViewPlugin::with_device_opener(Arc::new(|| Err(DriverDeviceError::Unsupported)));

    assert!(!plugin.can_attach(&fake_process()));
    assert!(plugin.create_instance(&fake_process()).is_err());
}

#[test]
fn plugin_attaches_when_driver_protocol_matches() {
    let device = Arc::new(FakeDriverDevice::new(SQUALR_DRIVER_PROTOCOL_VERSION));
    let plugin = KernelDriverMemoryViewPlugin::with_device_opener(opener_for(device));

    assert!(plugin.can_attach(&fake_process()));
    assert!(plugin.create_instance(&fake_process()).is_ok());
}

#[test]
fn plugin_refuses_driver_with_mismatched_protocol() {
    let device = Arc::new(FakeDriverDevice::new(SQUALR_DRIVER_PROTOCOL_VERSION + 1));
    let plugin = KernelDriverMemoryViewPlugin::with_device_opener(opener_for(device));

    assert!(!plugin.can_attach(&fake_process()));
}

#[test]
fn device_cache_reuses_probe_results_within_the_interval() {
    let device = Arc::new(FakeDriverDevice::new(SQUALR_DRIVER_PROTOCOL_VERSION));
    let device_cache = DeviceCache::new(opener_for(device.clone()), Duration::from_secs(60));

    for _ in 0..10 {
        assert!(device_cache.get_device().is_some());
    }

    assert_eq!(device.ping_count.load(Ordering::SeqCst), 1);
}

#[cfg(not(target_os = "windows"))]
#[test]
fn platform_driver_is_unsupported_off_windows() {
    assert_eq!(crate::device::open_platform_driver_device().err(), Some(DriverDeviceError::Unsupported));
}
