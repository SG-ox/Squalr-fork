//! Walks and filters the target's address space using driver region queries.
//! The filter rules mirror the native Windows memory queryer so scans see the same regions either way.

use crate::protocol::DriverMemoryRegion;
use squalr_engine_api::structures::memory::normalized_region::NormalizedRegion;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_PRIVATE: u32 = 0x2_0000;
pub const MEM_MAPPED: u32 = 0x4_0000;
pub const MEM_IMAGE: u32 = 0x100_0000;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;

/// Protection categories, matching `MemoryProtectionEnum` in the native target crate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProtectionSelection {
    pub write: bool,
    pub execute: bool,
    pub copy_on_write: bool,
}

impl ProtectionSelection {
    /// Converts the selection into the Windows page protection bits it covers.
    pub fn to_page_protection_flags(&self) -> u32 {
        let mut page_protection_flags = 0;

        if self.write {
            page_protection_flags |= PAGE_READWRITE | PAGE_EXECUTE_READWRITE;
        }

        if self.execute {
            page_protection_flags |= PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        }

        if self.copy_on_write {
            page_protection_flags |= PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
        }

        page_protection_flags
    }
}

/// Memory types a scan may include.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TypeSelection {
    pub none: bool,
    pub private: bool,
    pub image: bool,
    pub mapped: bool,
}

/// Decides which committed regions are returned to the scanner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionFilter {
    pub required_protection: ProtectionSelection,
    pub excluded_protection: ProtectionSelection,
    pub allowed_types: TypeSelection,
    /// First address of the scan window.
    pub start_address: u64,
    /// Last address of the scan window. A region must end at or before this address.
    pub end_address: u64,
}

impl RegionFilter {
    /// Returns true when a region should be scanned.
    pub fn accepts(
        &self,
        region: &DriverMemoryRegion,
    ) -> bool {
        if region.state != MEM_COMMIT {
            return false;
        }

        // Guard pages back thread stack growth. Touching them from another context can change the target's behavior, so they are never scanned.
        if region.protect & (PAGE_GUARD | PAGE_NOACCESS) != 0 {
            return false;
        }

        let is_type_allowed = match region.region_type {
            0 => self.allowed_types.none,
            MEM_PRIVATE => self.allowed_types.private,
            MEM_IMAGE => self.allowed_types.image,
            MEM_MAPPED => self.allowed_types.mapped,
            _ => false,
        };

        if !is_type_allowed {
            return false;
        }

        let required_flags = self.required_protection.to_page_protection_flags();

        if required_flags != 0 && region.protect & required_flags == 0 {
            return false;
        }

        let excluded_flags = self.excluded_protection.to_page_protection_flags();

        if excluded_flags != 0 && region.protect & excluded_flags != 0 {
            return false;
        }

        let region_end_address = region.base_address.saturating_add(region.region_size);

        region.base_address >= self.start_address && region_end_address <= self.end_address
    }

    /// Walks the address space from `start_address` to `end_address`, querying one region at a time.
    /// The walk stops at the first failed query, an empty region, or a region that does not advance.
    pub fn collect_regions<QueryFunction>(
        &self,
        mut query_region: QueryFunction,
    ) -> Vec<NormalizedRegion>
    where
        QueryFunction: FnMut(u64) -> Option<DriverMemoryRegion>,
    {
        let mut regions = Vec::new();
        let mut query_address = self.start_address;

        while query_address < self.end_address {
            let Some(region) = query_region(query_address) else {
                break;
            };

            let region_end_address = region.base_address.saturating_add(region.region_size);

            if region.region_size == 0 || region_end_address <= query_address {
                log::debug!(
                    "Kernel driver region walk stopped at {:#X}: the driver returned a region that does not advance.",
                    query_address
                );
                break;
            }

            if self.accepts(&region) {
                regions.push(NormalizedRegion::new(region.base_address, region.region_size));
            }

            query_address = region_end_address;
        }

        regions
    }
}
