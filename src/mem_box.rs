use std::ffi::c_void;
use std::mem;
use std::ptr;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualProtect,
};
use windows_sys::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use memchr::{memchr_iter, memmem};

pub fn scan_bytes(hay: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    let plen: usize = pattern.len();
    if plen == 0 || hay.len() < plen {
        return None;
    }

    if pattern.iter().all(|p: &Option<u8>| p.is_none()) {
        return Some(0);
    }

    if pattern.iter().all(|p: &Option<u8>| p.is_some()) {
        let pat_bytes: Vec<u8> = pattern.iter().map(|p: &Option<u8>| p.unwrap()).collect();
        return memmem::find(hay, &pat_bytes);
    }

    let fc_idx: usize = pattern.iter().position(|p: &Option<u8>| p.is_some()).unwrap();
    let fc_byte: u8 = pattern[fc_idx].unwrap();
    let max_start: usize = hay.len() - plen;
    let search_end: usize = fc_idx + max_start + 1;
    let search_area: &[u8] = &hay[fc_idx..search_end];

    for rel in memchr_iter(fc_byte, search_area) {
        let start: usize = rel;
        let mut ok: bool = true;
        for j in 0..plen {
            match pattern[j] {
                Some(b) => {
                    if hay[start + j] != b {
                        ok = false;
                        break;
                    }
                }
                None => {}
            }
        }
        if ok {
            return Some(start);
        }
    }
    None
}

pub struct ModuleContext {
    pub module_base: usize,
    pub module_size: usize,
}

impl ModuleContext {
    pub fn current() -> Option<Self> {
        unsafe {
            let h_mod: HMODULE = GetModuleHandleW(ptr::null::<u16>());
            if h_mod == std::ptr::null_mut() {
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

#[derive(Clone, Copy, Debug)]
pub struct LocalPtr {
    pub address: usize,
}

impl LocalPtr {
    pub fn offset(&self, off: isize) -> Option<LocalPtr> {
        if off >= 0 {
            let add: usize = off as usize;
            self.address.checked_add(add).map(|a: usize| LocalPtr { address: a })
        } else {
            let sub: usize = (-off) as usize;
            if self.address < sub {
                None
            } else {
                Some(LocalPtr { address: self.address - sub })
            }
        }
    }

    pub fn read_bytes(&self, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        unsafe {
            let ptr: *const u8 = self.address as *const u8;
            if ptr.is_null() {
                return None;
            }
            let slice: &[u8] = std::slice::from_raw_parts(ptr, len);
            Some(slice.to_vec())
        }
    }

    pub fn read_i32_le(&self) -> Option<i32> {
        let b: Vec<u8> = self.read_bytes(4)?;
        Some(i32::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn dereference(&self) -> Option<LocalPtr> {
        if cfg!(target_pointer_width = "64") {
            let b: Vec<u8> = self.read_bytes(8)?;
            let ptr: usize = usize::from_le_bytes(b.try_into().unwrap());
            Some(LocalPtr { address: ptr })
        } else {
            let b: Vec<u8> = self.read_bytes(4)?;
            let ptr32: usize = u32::from_le_bytes(b.try_into().unwrap()) as usize;
            Some(LocalPtr { address: ptr32 })
            }
    }

    pub fn deref(&self) -> Option<Self> {
        self.dereference()
    }

    pub fn rip_relative(&self, offset_offset: isize, instruction_len: isize) -> Option<Self> {
        let disp: isize = self.offset(offset_offset)?.read_i32_le()? as isize;
        self.offset(instruction_len + disp)
    }

    pub fn write_f32(&self, v: f32) -> Option<()> {
        let bytes: [u8; 4] = v.to_le_bytes();
        self.write_bytes(&bytes)
    }

    pub fn write_bytes(&self, data: &[u8]) -> Option<()> {
        if data.is_empty() {
            return Some(());
        }
        unsafe {
            let dst: *mut u8 = self.address as *mut u8;
            if dst.is_null() {
                return None;
            }
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
            Some(())
        }
    }

    pub fn write_bytes_protected(&self, data: &[u8]) -> Option<()> {
        if data.is_empty() {
            return Some(());
        }
        unsafe {
            const PAGE_SIZE: usize = 0x1000;
            let start_page: usize = self.address & !(PAGE_SIZE - 1);
            let mut old: PAGE_PROTECTION_FLAGS = 0;
            let ok: i32 = VirtualProtect(
                start_page as *mut c_void,
                PAGE_SIZE,
                PAGE_READWRITE,
                &mut old as *mut _,
            );
            if ok == 0 {
                return None;
            }
            let res: Option<()> = self.write_bytes(data);
            let _ = VirtualProtect(
                start_page as *mut c_void,
                PAGE_SIZE,
                old,
                &mut old as *mut _,
            );
            res
        }
    }

    pub fn write_f32_protected(&self, v: f32) -> Option<()> {
        self.write_bytes_protected(&v.to_le_bytes())
    }

    pub fn chain(self) -> LocalPtrChain {
        LocalPtrChain { current: self }
    }
}

pub struct LocalPtrChain {
    current: LocalPtr,
}

impl LocalPtrChain {
    pub fn offset(mut self, off: isize) -> Option<Self> {
        self.current = self.current.offset(off)?;
        Some(self)
    }

    pub fn deref(mut self) -> Option<Self> {
        self.current = self.current.dereference()?;
        Some(self)
    }

    pub fn finish(self) -> LocalPtr {
        self.current
    }
}
