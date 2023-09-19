// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! KeysasUsbMonitor detect and keep track of USB devices plugged in the computer

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![forbid(private_in_public)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use anyhow::anyhow;
use std::{thread, time, fmt};
use std::ffi::{CString, CStr, c_void};
use windows::Win32::Storage::FileSystem::QueryDosDeviceA;
use windows::Win32::Storage::FileSystem::GetLogicalDrives;
use windows::core::PCSTR;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Storage::FileSystem::CreateFileA;
use windows::Win32::Storage::FileSystem::FILE_SHARE_MODE;
use windows::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::SetFilePointer;
use windows::Win32::Storage::FileSystem::SET_FILE_POINTER_MOVE_METHOD;
use windows::Win32::Storage::FileSystem::INVALID_SET_FILE_POINTER;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::ReadFile;
use windows::Win32::System::Ioctl::VOLUME_DISK_EXTENTS;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::Storage::FileSystem::IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS;
use windows::Win32::System::Ioctl::RemovableMedia;
use windows::Win32::Devices::Usb::USB_DEVICE_DESCRIPTOR_TYPE;
use windows::Win32::Devices::Usb::USB_STRING_DESCRIPTOR_TYPE;
use windows::Win32::Devices::Usb::USB_DEVICE_DESCRIPTOR;
use windows::Win32::Devices::Usb::USBSCAN_GET_DESCRIPTOR;
use windows::Win32::Devices::Usb::IOCTL_GET_USB_DESCRIPTOR;
use windows::Win32::Devices::Usb::IOCTL_USB_GET_NODE_CONNECTION_INFORMATION;
use windows::Win32::System::Ioctl::IOCTL_DISK_GET_DRIVE_GEOMETRY;
use windows::Win32::System::Ioctl::DISK_GEOMETRY;
use windows::Win32::Devices::Usb::WinUsb_Initialize;
use windows::Win32::Devices::Usb::WinUsb_GetDescriptor;
use windows::Win32::Devices::Usb::WinUsb_Free;
use windows::Win32::Devices::Usb::WINUSB_INTERFACE_HANDLE;
use windows::Win32::Devices::Usb::URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE;
use std::mem::size_of;

struct UsbInfo {
    bcdUSB: u16,
    idVendor: u16,
    idProduct: u16,
    bcdDevice: u16
}

impl fmt::Debug for UsbInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "USB version: {}, Vendor ID: {}, Product ID: {}, Device version: {}",
            self.bcdUSB,
            self.idVendor,
            self.idProduct,
            self.bcdDevice
        )
    }
}

#[derive(Debug)]
struct UsbDevice {
    volume_index: u8,
    volume_name: CString,
    physical_name: CString,
    device_info: UsbInfo,
    authorized: bool
}

/// Hold list of the USB devices
#[derive(Debug)]
pub struct KeysasUsbMonitor {
    device_list: Vec<UsbDevice>
}

/// Read the raw content of a physical disk
/// 
/// # Arguments:
/// 
/// * 'disk_name' - Disk physical name (UTF8), like "\\Device\\HarddiskVolume3"
/// * 'first_sector' - Number of the first sector to read
/// * 'content' - Reference to a buffer to hold the content read, must be at least nb_sector * 512 bytes
fn read_sectors(disk_name: &CStr, first_sector: i32, content: &mut [u8]) -> Result<(), anyhow::Error> {
    // According to https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask GENERIC_READ is 31th bit
    // According to https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea, FILE_SHARE_READ is 0x00000001
    let file_handle = unsafe {
        match CreateFileA(
            PCSTR(disk_name.as_ptr() as *const u8),
            0xC0000000,
            FILE_SHARE_MODE(0x00000001),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default()) {
                Ok(f) => f,
                Err(e) => {
                    println!("Failed to open file: {e}");
                    let err = GetLastError();
                    return Err(anyhow!("Failed to open device: {:?}", err));
                }
            }
    };

    /* Set pointer to the specified sector */
    unsafe {
        if INVALID_SET_FILE_POINTER == SetFilePointer(
            file_handle,
            first_sector*512,
            None,
            SET_FILE_POINTER_MOVE_METHOD(0)) {
                let err = GetLastError();
                let _ = CloseHandle(file_handle);
                return Err(anyhow!("Failed to move pointer: {:?}", err));
            }
    };

    /* Read the content of the sector */
    let mut nb_bytes_read: u32 = 0;

    unsafe {
        if let Err(e) = ReadFile(
            file_handle, 
            Some(content), 
            Some(&mut nb_bytes_read),
            None) {
                println!("Failed to read file: {e}");
                let err = GetLastError();
                let _ = CloseHandle(file_handle);
                return Err(anyhow!("Failed to read file: {:?}", err));
            }
    }

    /* Close file handle */
    unsafe {        
        let _ = CloseHandle(file_handle);
    }

    return Ok(());
}

/// List all the existing volume on the system and returns a bitmask containing the new ones
/// 
/// # Arguments
/// 
/// * 'current_volumes' - reference to the current volumes list. It is updated with the new list
fn detect_new_volumes(current_volumes: &mut u32) -> Result<u32, anyhow::Error> {
    // Get list of existing logical drives as a bitmask
    let bitmask = unsafe {
        GetLogicalDrives()
    };

    if 0 == bitmask {
        unsafe {
            let err = match GetLastError() {
                Ok(_) => String::from("Error unknown"),
                Err(e) => e.message().to_string_lossy()
            };
            return Err(anyhow!("Failed to get logical drive bitmask: {err}"));
        }
    }

    // Compare with the previous iteration and isolate new ones
    let new_drives = (*current_volumes | bitmask) ^ *current_volumes;

    // Update the volume list
    *current_volumes = bitmask;

    return Ok(new_drives);
}

/// Get the info of the physical disk name from the logical drive number if it is a removable device
/// 
/// # Arguments
/// 
/// * 'volume_number' - Index of the volume in the system
fn get_usb_device_info(volume_number: u8) -> Result<UsbDevice, anyhow::Error> {
    // Create name of the logical volume from the index
    let mut logical_name: [u8; 7] = [92, 92, 46, 92, 65+volume_number, 58, 0];

    println!("Logical name: {:?}", logical_name);

    // Get a handle to the volume
    let volume_handle = unsafe {
        match CreateFileA(
            PCSTR(logical_name.as_ptr() as *const u8),
            0x80000000,
            FILE_SHARE_MODE(0x00000003),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default()) {
                Ok(f) => f,
                Err(e) => {
                    println!("Failed to open volume: {e}");
                    let err = match GetLastError() {
                        Ok(_) => String::from("Unknown error"),
                        Err(e) => e.message().to_string_lossy()
                    };
                    return Err(anyhow!("Failed to open volume: {err}"));
                }
            }
    };

    // Get information structure of the volume
    let mut extents: VOLUME_DISK_EXTENTS = VOLUME_DISK_EXTENTS::default();
    unsafe {
        if let Err(e) = DeviceIoControl(
            volume_handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            0,
            Some(&mut extents as *mut _ as *mut c_void),
            size_of::<VOLUME_DISK_EXTENTS>() as u32, // should not overflow
            None,
            None
        ) {
            let _ = CloseHandle(volume_handle);
            return Err(anyhow!("Failed to get volume disk extents: {:?}", e.message().to_string_lossy()));
        }

        // Volume handle no longer needed
        let _ = CloseHandle(volume_handle);
    }

    // If the volume is spread over more than one disk, abort
    // TODO - This could be improved to support more partition format
    if 1 != extents.NumberOfDiskExtents {
        return Err(anyhow!("Extended volume not supported"));
    }

    // Create the physical drive name
    let physical_name = match CString::new(format!("\\\\.\\PHYSICALDRIVE{index}", 
                                        index = extents.Extents[0].DiskNumber)) {
        Ok(n) => n,
        Err(e) => {
            return Err(anyhow!("Failed to create physical name: {e}"));
        }
    };

    println!("Physical name: {:?}", physical_name);

    // Get a handle to the physical drive
    let physical_handle = unsafe {
        match CreateFileA(
            PCSTR(physical_name.as_ptr() as *const u8),
            0xC0000000, // GENERIC_WRITE | GENERIC_READ
            FILE_SHARE_MODE(0x00000003), // FILE_SHARE_READ | FILE_SHARE_WRITE
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0x80 | 0x40000000), // FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_OVERLAPPED
            HANDLE::default()) {
                Ok(f) => f,
                Err(e) => {
                    println!("Failed to open physical handle: {e}");
                    let err = match GetLastError() {
                        Ok(_) => String::from("Unknown error"),
                        Err(e) => e.message().to_string_lossy()
                    };
                    return Err(anyhow!("Failed to open physical handle: {err}"));
                }
            }
    };

    // Check that the disk is of RemovableMedia type
    let mut geometry: DISK_GEOMETRY = DISK_GEOMETRY::default();
    unsafe {
        if let Err(e) = DeviceIoControl(
            physical_handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            None,
            0,
            Some(&mut geometry as *mut _ as *mut c_void),
            size_of::<DISK_GEOMETRY>() as u32, // Should not overflow
            None,
            None
        ) {
            let _ = CloseHandle(physical_handle);
            return Err(anyhow!("Failed to get disk geometry: {:?}", e.message().to_string_lossy()));
        }
    }

    // Keep only RemovableMedia to filter USB devices
    if RemovableMedia != geometry.MediaType {
        unsafe {
            let _ = CloseHandle(physical_handle);
        }
        return Err(anyhow!("Media type not supported"));
    }

    // Get product information
    let mut device_descriptor: USB_DEVICE_DESCRIPTOR = USB_DEVICE_DESCRIPTOR::default();
    let usb_desc = USBSCAN_GET_DESCRIPTOR {
        DescriptorType: USB_DEVICE_DESCRIPTOR_TYPE as u8, // Should not overflow (1u32)
        Index: 0,
        LanguageId: 0
    };

    unsafe {
        if let Err(e) = DeviceIoControl(
            physical_handle,
            IOCTL_USB_GET_NODE_CONNECTION_INFORMATION,
            Some(&usb_desc as *const _ as *const c_void),
            size_of::<USBSCAN_GET_DESCRIPTOR>() as u32, // Should not overflow
            Some(&mut device_descriptor as *mut _ as *mut c_void),
            size_of::<USB_DEVICE_DESCRIPTOR>() as u32, // Should not overflow
            None,
            None
        ) {
            let _ = CloseHandle(physical_handle);
            return Err(anyhow!("Failed to get product information: {:?}", e.message().to_string_lossy()));
        }
    }

    /*
    let mut winusb_handle = WINUSB_INTERFACE_HANDLE::default();
    let mut device_descriptor: [u8; 1024] = [0; 1024];
    let mut size_read: u32 = 0;

    unsafe {
        if let Err(e) = WinUsb_Initialize(
            physical_handle,
            &mut winusb_handle as *mut _
        ) {
            let _ = CloseHandle(physical_handle);
            return Err(anyhow!("Failed to initialize Win USB handle: {:?}", e.message().to_string_lossy()));
        }

        if let Err(e) = WinUsb_GetDescriptor(
            winusb_handle,
            USB_DEVICE_DESCRIPTOR_TYPE as u8,
            0,
            0x409, // Ask for English
            Some(&mut device_descriptor),
            &mut size_read as *mut u32
        ) {
            let _ = CloseHandle(physical_handle);
            let _ = WinUsb_Free(winusb_handle);
            return Err(anyhow!("Failed to get USB descriptor: {:?}", e.message().to_string_lossy()));
        }
        
        let _ = WinUsb_Free(winusb_handle);
    }
    */

    //println!("Device descriptor: {:?}", device_descriptor);

    // Close physical handle
    unsafe {
        let _ = CloseHandle(physical_handle);
    }
    
    // Instantiate a new UsbDevice
    let mut device = UsbDevice {
        volume_index: volume_number,
        volume_name: CString::from_vec_with_nul(logical_name.to_vec())?, // Built the line before so should be ok
        physical_name,
        device_info: UsbInfo{
            bcdUSB: 0, //device_descriptor.bcdUSB,
            idVendor: 0, //device_descriptor.idVendor,
            idProduct: 0, //device_descriptor.idProduct,
            bcdDevice: 0 //device_descriptor.bcdDevice
        },
        authorized: false
    };

    return Ok(device);
}

/// Validate the signature of the device
/// 
/// # Arguments
/// 
/// * 'device_data' - Device descriptor of the new USB device
/// * 'first_sectors' - Content of the first on the device
fn validate_device_signature(device_descriptor: &USB_DEVICE_DESCRIPTOR, first_sectors: &[u8; 2048]) -> Result<bool, anyhow::Error> {

    Ok(false)
}

impl KeysasUsbMonitor {
    pub fn start_usb_monitor() -> Result<(), anyhow::Error> {
        thread::spawn(|| {
            let sleep_dur = time::Duration::from_secs(2);
            let mut logical_drives: u32 = 0;
            // Buffer to hold physical name for the drive
            let mut physical_buffer: [u8; 1024] = [0; 1024];
            // Construct the logical name for the drive, for example "C:"
            let mut logical_name: [u8; 3] = [0, 58, 0];

            loop {
                // Get list of new volumes on the system
                let new_drives = match detect_new_volumes(&mut logical_drives) {
                    Ok(b) => b,
                    Err(e) => {
                        println!("Called to detect_new_volumes failed: {e}");
                        continue;
                    }
                };

                // Check new volumes
                if new_drives.count_ones() > 0 {
                    // At least one new drive is found
                    for i in 0..32 {
                        if 1 == ((new_drives >> i) & 1) {
                            let new_device = match get_usb_device_info(i) {
                                Ok(d) => d,
                                Err(e) => {
                                    println!("Failed to get device info: {e}");
                                    continue;
                                }
                            };

                            println!("New device: {:?}", new_device);

                            // Read the content of the disk MBR and first sectors
                            let mut content: [u8; 2048] = [0; 2048];
                            match read_sectors(&new_device.physical_name, 0, &mut content) {
                                Ok(_) => {
                                    println!("First section is: {:?}", content);
                                },
                                Err(e) => {
                                    println!("Failed to read new drive: {e}");
                                }
                            }

                            // Validate the signature of the MBR
                        }
                    }
                }

                thread::sleep(sleep_dur);
            }
        });

        Ok(())
    }
}