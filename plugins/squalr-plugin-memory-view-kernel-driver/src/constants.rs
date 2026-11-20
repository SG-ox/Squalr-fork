pub const KERNEL_DRIVER_PLUGIN_ID: &str = "builtin.memory-view.kernel-driver";
pub const KERNEL_DRIVER_PLUGIN_DISPLAY_NAME: &str = "Kernel Driver Memory View";
pub const KERNEL_DRIVER_PLUGIN_DESCRIPTION: &str =
    "Routes process memory reads, writes, and region queries through the Squalr kernel driver. Windows only. Requires the driver to be installed and running.";

/// User-mode path of the driver's symbolic link. Must match `SQUALR_SYMBOLIC_LINK_NAME` in `driver/squalr_driver_protocol.h`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const KERNEL_DRIVER_DEVICE_PATH: &str = r"\\.\Squalr";

/// How long a driver availability probe result is trusted before probing again.
pub const DRIVER_PROBE_INTERVAL_MILLISECONDS: u64 = 5_000;

/// The lowest address that Windows maps for user-mode programs.
pub const WINDOWS_MIN_USERMODE_ADDRESS: u64 = 0x10000;

/// The highest user-mode address for 32-bit processes.
pub const WINDOWS_MAX_USERMODE_ADDRESS_32: u64 = 0x7FFF_FFFF;

/// The highest user-mode address for 64-bit processes.
pub const WINDOWS_MAX_USERMODE_ADDRESS_64: u64 = 0x7FFF_FFFF_FFFF;
