use std::ptr::null_mut;
use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::NULL;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
};
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};

pub const GAME_MANAGER_IMP: [Option<u8>; 17] = [
    Some(0x48),
    Some(0x8B),
    Some(0x05),
    None,
    None,
    None,
    None,
    Some(0x48),
    Some(0x8B),
    Some(0x58),
    Some(0x38),
    Some(0x48),
    Some(0x85),
    Some(0xDB),
    Some(0x74),
    None,
    Some(0xF6),
];

pub const NET_SEASON_MANAGER: [Option<u8>; 17] = [
    Some(0x48),
    Some(0x8B),
    Some(0x0D),
    None,
    None,
    None,
    None,
    Some(0x48),
    Some(0x85),
    Some(0xC9),
    Some(0x74),
    None,
    Some(0x48),
    Some(0x8B),
    Some(0x49),
    Some(0x18),
    Some(0xE8),
];

pub const KATANA_MAIN_APP: [Option<u8>; 12] = [
    Some(0x48),
    Some(0x8B),
    Some(0x15),
    None,
    None,
    None,
    None,
    Some(0x45),
    Some(0x32),
    Some(0xC0),
    Some(0x85),
    Some(0xC9),
];

#[derive(Debug, Clone)]
pub enum MemError {
    WinApi(String),
    NullPointer,
    PatternNotFound(String),
}

#[derive(Clone)]
pub struct MemoryPointer {
    pub handle: HANDLE,
    pub address: usize,
    pub module_base: usize,
    pub module_size: u32,
    pub module_name: String,
}

impl MemoryPointer {
    pub fn from_pid(pid: u32, module_name: &str) -> Result<Self, MemError> {
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if handle.is_null() {
                return Err(MemError::WinApi("OpenProcess failed".into()));
            }

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
            if snapshot == NULL {
                CloseHandle(handle);
                return Err(MemError::WinApi("CreateToolhelp32Snapshot failed".into()));
            }

            let mut me32: MODULEENTRY32W = std::mem::zeroed();
            me32.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

            let mut module_base = 0usize;
            let mut module_size = 0u32;
            let mut module_name_found = String::new();

            if Module32FirstW(snapshot, &mut me32) != FALSE {
                loop {
                    let name = String::from_utf16_lossy(
                        &me32.szModule
                            .iter()
                            .take_while(|&&c| c != 0)
                            .cloned()
                            .collect::<Vec<u16>>(),
                    );

                    if name.to_lowercase() == module_name.to_lowercase() {
                        module_base = me32.modBaseAddr as usize;
                        module_size = me32.modBaseSize;
                        module_name_found = name;
                        break;
                    }

                    if Module32NextW(snapshot, &mut me32) == FALSE {
                        break;
                    }
                }
            }

            if module_base == 0 {
                CloseHandle(handle);
                return Err(MemError::WinApi("Module not found".into()));
            }

            Ok(Self {
                handle,
                address: module_base,
                module_base,
                module_size,
                module_name: module_name_found,
            })
        }
    }

    pub fn offset(&self, off: isize) -> Result<Self, MemError> {
        let new_address = if off >= 0 {
            self.address
                .checked_add(off as usize)
                .ok_or(MemError::NullPointer)?
        } else {
            self.address
                .checked_sub((-off) as usize)
                .ok_or(MemError::NullPointer)?
        };

        Ok(Self {
            handle: self.handle,
            address: new_address,
            module_base: self.module_base,
            module_size: self.module_size,
            module_name: self.module_name.clone(),
        })
    }

    pub fn dereference(&self) -> Result<Self, MemError> {
        let buf = self.read_u64()?;
        Ok(MemoryPointer {
            handle: self.handle,
            address: buf as usize,
            module_base: self.module_base,
            module_size: self.module_size,
            module_name: self.module_name.clone(),
        })
    }

    pub fn read_f32(&self) -> Result<f32, MemError> {
        let mut buf: f32 = 0.0;
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.address as *const winapi::ctypes::c_void,
                &mut buf as *mut f32 as *mut winapi::ctypes::c_void,
                std::mem::size_of::<f32>(),
                null_mut(),
            )
        };

        if res == 0 {
            return Err(MemError::WinApi(format!(
                "ReadProcessMemory failed at {:#X}",
                self.address
            )));
        }

        Ok(buf)
    }

    pub fn write_f32(&self, value: f32) -> Result<(), MemError> {
        let res = unsafe {
            WriteProcessMemory(
                self.handle,
                self.address as *mut winapi::ctypes::c_void,
                &value as *const f32 as *const winapi::ctypes::c_void,
                std::mem::size_of::<f32>(),
                null_mut(),
            )
        };

        if res == 0 {
            return Err(MemError::WinApi(format!(
                "WriteProcessMemory failed at {:#X}",
                self.address
            )));
        }

        Ok(())
    }

    pub fn read_i32(&self) -> Result<i32, MemError> {
        let mut buf: i32 = 0;
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.address as *const winapi::ctypes::c_void,
                &mut buf as *mut i32 as *mut winapi::ctypes::c_void,
                std::mem::size_of::<i32>(),
                null_mut(),
            )
        };

        if res == 0 {
            return Err(MemError::WinApi(format!(
                "ReadProcessMemory failed at {:#X}",
                self.address
            )));
        }

        Ok(buf)
    }

    pub fn read_u64(&self) -> Result<u64, MemError> {
        let mut buf: u64 = 0;
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.address as *const winapi::ctypes::c_void,
                &mut buf as *mut u64 as *mut winapi::ctypes::c_void,
                std::mem::size_of::<u64>(),
                null_mut(),
            )
        };

        if res == 0 {
            return Err(MemError::WinApi(format!(
                "ReadProcessMemory failed at {:#X}",
                self.address
            )));
        }

        Ok(buf)
    }

    pub fn read_bytes(&self, size: usize) -> Result<Vec<u8>, MemError> {
        let mut buffer = vec![0u8; size];
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.address as *const winapi::ctypes::c_void,
                buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
                size,
                null_mut(),
            )
        };

        if res == 0 {
            return Err(MemError::WinApi(format!(
                "ReadProcessMemory failed at {:#X}",
                self.address
            )));
        }

        Ok(buffer)
    }

    pub fn pattern_scan(&self, pattern: &[Option<u8>]) -> Result<Self, MemError> {
        let mut buffer = vec![0u8; self.module_size as usize];
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.module_base as *const winapi::ctypes::c_void,
                buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
                self.module_size as usize,
                null_mut(),
            )
        };

        if res == 0 {
            return Err(MemError::WinApi("Failed to read module memory".into()));
        }

        for i in 0..buffer.len() - pattern.len() {
            let mut found = true;

            for j in 0..pattern.len() {
                if let Some(byte) = pattern[j] {
                    if buffer[i + j] != byte {
                        found = false;
                        break;
                    }
                }
            }

            if found {
                return Ok(Self {
                    handle: self.handle,
                    address: self.module_base + i,
                    module_base: self.module_base,
                    module_size: self.module_size,
                    module_name: self.module_name.clone(),
                });
            }
        }

        Err(MemError::PatternNotFound("Pattern not found".into()))
    }
}