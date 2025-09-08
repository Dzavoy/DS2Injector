use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

use sysinfo::System;

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
            let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if handle == 0 as HANDLE {
                return Err(MemError::WinApi("OpenProcess failed".into()));
            }

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
            if snapshot == 0 as HANDLE{
                CloseHandle(handle);
                return Err(MemError::WinApi("CreateToolhelp32Snapshot failed".into()));
            }

            let mut me32: MODULEENTRY32W = std::mem::zeroed();
            me32.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

            let mut module_base = 0usize;
            let mut module_size = 0u32;
            let mut module_name_found = String::new();

            if Module32FirstW(snapshot, &mut me32) != 0 {
                loop {
                    let name = String::from_utf16_lossy(
                        &me32.szModule
                            .iter()
                            .take_while(|&&c| c != 0)
                            .cloned()
                            .collect::<Vec<u16>>(),
                    );

                    if name.eq_ignore_ascii_case(module_name) {
                        module_base = me32.modBaseAddr as usize;
                        module_size = me32.modBaseSize;
                        module_name_found = name;
                        break;
                    }

                    if Module32NextW(snapshot, &mut me32) == 0 {
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
            self.address.checked_add(off as usize).ok_or(MemError::NullPointer)?
        } else {
            self.address.checked_sub((-off) as usize).ok_or(MemError::NullPointer)?
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

    pub fn pointer_walk(&self, offsets: &[isize]) -> Result<Self, MemError> {
        if offsets.is_empty() {
            return Ok(self.clone());
        }

        let mut current = self.offset(offsets[0])?;
        for &offset in &offsets[1..] {
            let next_addr = current.read_u64()? as usize;
            current = MemoryPointer {
                handle: self.handle,
                address: next_addr,
                module_base: self.module_base,
                module_size: self.module_size,
                module_name: self.module_name.clone(),
            }
            .offset(offset)?;
        }
        Ok(current)
    }

    pub fn find_process(name: &str) -> Result<u32, MemError> {
        let mut sys = System::new_all();
        sys.refresh_all();

        sys.processes()
            .iter()
            .find(|(_, p)| p.name().eq_ignore_ascii_case(name))
            .map(|(pid, _)| pid.as_u32())
            .ok_or_else(|| MemError::WinApi("Process not found".into()))
    }

    pub fn read_f32(&self) -> Result<f32, MemError> {
        let mut buf: f32 = 0.0;
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.address as *const _,
                &mut buf as *mut _ as *mut _,
                std::mem::size_of::<f32>(),
                null_mut(),
            )
        };
        if res == 0 {
            return Err(MemError::WinApi(format!("ReadProcessMemory failed at {:#X}", self.address)));
        }
        Ok(buf)
    }

    pub fn write_f32(&self, value: f32) -> Result<(), MemError> {
        let res = unsafe {
            WriteProcessMemory(
                self.handle,
                self.address as *mut _,
                &value as *const _ as *const _,
                std::mem::size_of::<f32>(),
                null_mut(),
            )
        };
        if res == 0 {
            return Err(MemError::WinApi(format!("WriteProcessMemory failed at {:#X}", self.address)));
        }
        Ok(())
    }

    pub fn read_i32(&self) -> Result<i32, MemError> {
        let mut buf: i32 = 0;
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.address as *const _,
                &mut buf as *mut _ as *mut _,
                std::mem::size_of::<i32>(),
                null_mut(),
            )
        };
        if res == 0 {
            return Err(MemError::WinApi(format!("ReadProcessMemory failed at {:#X}", self.address)));
        }
        Ok(buf)
    }

    pub fn write_i32(&self, value: i32) -> Result<(), MemError> {
        let res = unsafe {
            WriteProcessMemory(
                self.handle,
                self.address as *mut _,
                &value as *const _ as *const _,
                std::mem::size_of::<i32>(),
                null_mut(),
            )
        };
        if res == 0 {
            return Err(MemError::WinApi(format!("WriteProcessMemory failed at {:#X}", self.address)));
        }
        Ok(())
    }

    pub fn read_u64(&self) -> Result<u64, MemError> {
        let mut buf: u64 = 0;
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.address as *const _,
                &mut buf as *mut _ as *mut _,
                std::mem::size_of::<u64>(),
                null_mut(),
            )
        };
        if res == 0 {
            return Err(MemError::WinApi(format!("ReadProcessMemory failed at {:#X}", self.address)));
        }
        Ok(buf)
    }

    pub fn read_bytes(&self, size: usize) -> Result<Vec<u8>, MemError> {
        let mut buffer = vec![0u8; size];
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                null_mut(),
            )
        };
        if res == 0 {
            return Err(MemError::WinApi(format!("ReadProcessMemory failed at {:#X}", self.address)));
        }
        Ok(buffer)
    }

    pub fn pattern_scan(&self, pattern: &[Option<u8>]) -> Result<Self, MemError> {
        let mut buffer = vec![0u8; self.module_size as usize];
        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                self.module_base as *const _,
                buffer.as_mut_ptr() as *mut _,
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