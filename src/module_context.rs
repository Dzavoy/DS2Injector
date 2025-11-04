use std::mem;
use std::ptr;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::local_ptr::LocalPtr;
use crate::scan::scan_bytes;

#[derive(Debug, Clone, Copy)]
pub struct ModuleContext {
    pub module_base: usize,
    pub module_size: usize,
}

impl ModuleContext {
    pub fn current() -> Option<Self> {
        unsafe {
            let h_mod: HMODULE = GetModuleHandleW(ptr::null::<u16>());
            if h_mod == ptr::null_mut() {
                return None;
            }
            let mut info: MODULEINFO = MODULEINFO {
                lpBaseOfDll: ptr::null_mut(),
                SizeOfImage: 0,
                EntryPoint: ptr::null_mut(),
            };
            let ok: i32 = GetModuleInformation(
                GetCurrentProcess(),
                h_mod,
                &mut info as *mut MODULEINFO,
                mem::size_of::<MODULEINFO>() as u32,
            );
            if ok == 0 {
                return None;
            }
            Some(ModuleContext {
                module_base: info.lpBaseOfDll as usize,
                module_size: info.SizeOfImage as usize,
            })
        }
    }

    pub fn pattern_scan(&self, pattern: &[Option<u8>]) -> Option<LocalPtr> {
        unsafe {
            let base: usize = self.module_base;
            let size: usize = self.module_size;
            if size == 0 || base == 0 {
                return None;
            }
            let hay: &[u8] = std::slice::from_raw_parts(base as *const u8, size);
            if let Some(idx) = scan_bytes(hay, pattern) {
                Some(LocalPtr {
                    address: base + idx,
                })
            } else {
                None
            }
        }
    }
}
