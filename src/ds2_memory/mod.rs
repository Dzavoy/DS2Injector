use crate::memory_pointer::{MemoryPointer, MemError};
mod addresses;
use addresses::{get_address_path, GAME_MANAGER_IMP};

pub struct Stats {
    base: MemoryPointer,
}

impl Stats {
    pub fn new(base: &MemoryPointer) -> Self {
        Self { base : base.clone() }
    }

    pub fn current_health(&self) -> Result<i32, MemError> {
        match get_address_path("current_hp") {
            Some(path) => {
                let ptr: MemoryPointer = self.base.pointer_walk(path)?;
                ptr.read_i32()
            },
            None => Err(MemError::PatternNotFound("current_hp address not found".into()))
        }
    }

    pub fn set_current_health(&self, value: i32) -> Result<(), MemError> {
        match get_address_path("current_hp") {
            Some(path) => {
                let ptr: MemoryPointer = self.base.pointer_walk(path)?;
                ptr.write_i32(value)
            },
            None => Err(MemError::PatternNotFound("current_hp address not found".into()))
        }
    }

    pub fn min_health(&self) -> Result<i32, MemError> {
        match get_address_path("min_hp") {
            Some(path) => {
                let ptr: MemoryPointer = self.base.pointer_walk(path)?;
                ptr.read_i32()
            },
            None => Err(MemError::PatternNotFound("min_hp address not found".into()))
        }
    }

    pub fn set_min_health(&self, value: i32) -> Result<(), MemError> {
        match get_address_path("min_hp") {
            Some(path) => {
                let ptr: MemoryPointer = self.base.pointer_walk(path)?;
                ptr.write_i32(value)
            },
            None => Err(MemError::PatternNotFound("min_hp address not found".into()))
        }
    }

    pub fn max_health(&self) -> Result<i32, MemError> {
                match get_address_path("max_hp") {
            Some(path) => {
                let ptr: MemoryPointer = self.base.pointer_walk(path)?;
                ptr.read_i32()
            },
            None => Err(MemError::PatternNotFound("max_hp address not found".into()))
        }
    }

    pub fn set_max_health(&self, value: i32) -> Result<(), MemError> {
        match get_address_path("max_hp") {
            Some(path) => {
                let ptr: MemoryPointer = self.base.pointer_walk(path)?;
                ptr.write_i32(value)
            },
            None => Err(MemError::PatternNotFound("max_hp address not found".into()))
        }
    }
}

pub struct ChrAnimState {
    base: MemoryPointer,
}

// TODO
impl ChrAnimState {
    pub fn new(base: MemoryPointer) -> Self {
        Self { base }
    }

    pub fn lock_roll_state(&self) -> Result<Vec<u8>, MemError> {
        match get_address_path("lock_roll") {
            Some(path) => {
                let ptr: MemoryPointer = self.base.pointer_walk(path)?;
                ptr.read_bytes(1)
            },
            None => Err(MemError::PatternNotFound("lock_roll address not found".into()))
        }
    }

}

pub struct MyCharacter {
    pub stats: Stats,
    pub chr_anim_state: ChrAnimState,
}

impl MyCharacter {
    pub fn new(root: MemoryPointer) -> Result<Self, MemError> {
        let pattern_match: MemoryPointer = root.pattern_scan(&GAME_MANAGER_IMP)?;
        
        let offset_bytes: Vec<u8> = pattern_match.offset(3)?.read_bytes(4)?;
        let offset: i32 = i32::from_le_bytes(offset_bytes.try_into().unwrap());
        
        // offset + 7
        let real_base: MemoryPointer = pattern_match.offset(offset as isize + 7)?.dereference()?;

        let stats: Stats = Stats::new(&real_base);
        let chr_anim_state: ChrAnimState = ChrAnimState::new(real_base);

        Ok(Self { stats, chr_anim_state })
    }
}

pub struct DS2Memory {
    pub my_character: MyCharacter,
}

impl DS2Memory {
    pub fn new() -> Result<Self, MemError> {
        let pid: u32 = MemoryPointer::find_process("DarkSoulsII.exe")?;
        let root: MemoryPointer = MemoryPointer::from_pid(pid, "DarkSoulsII.exe")?;
        let my_character: MyCharacter = MyCharacter::new(root)?;

        Ok(Self { my_character })
    }
}