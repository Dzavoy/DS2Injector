use std::ffi::c_void;

use windows_sys::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualProtect};

#[derive(Clone, Copy, Debug)]
pub struct LocalPtr {
    pub address: usize,
}

impl LocalPtr {
    pub fn offset(&self, off: isize) -> Option<LocalPtr> {
        if off >= 0 {
            let add: usize = off as usize;
            self.address
                .checked_add(add)
                .map(|a: usize| LocalPtr { address: a })
        } else {
            let sub: usize = (-off) as usize;
            if self.address < sub {
                None
            } else {
                Some(LocalPtr {
                    address: self.address - sub,
                })
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
            let ok = VirtualProtect(
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
