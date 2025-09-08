use std::collections::HashMap;
use lazy_static::lazy_static;

pub const GAME_MANAGER_IMP: [Option<u8>; 17] = [
    Some(0x48), Some(0x8B), Some(0x05), None, None, None, None, Some(0x48),
    Some(0x8B), Some(0x58), Some(0x38), Some(0x48), Some(0x85), Some(0xDB),
    Some(0x74), None, Some(0xF6),
];

pub const NET_SEASON_MANAGER: [Option<u8>; 17] = [
    Some(0x48), Some(0x8B), Some(0x0D), None, None, None, None, Some(0x48),
    Some(0x85), Some(0xC9), Some(0x74), None, Some(0x48), Some(0x8B),
    Some(0x49), Some(0x18), Some(0xE8),
];

pub const KATANA_MAIN_APP: [Option<u8>; 12] = [
    Some(0x48), Some(0x8B), Some(0x15), None, None, None, None, Some(0x45),
    Some(0x32), Some(0xC0), Some(0x85), Some(0xC9),
];

lazy_static! {
    pub static ref ADDRESS_MAP: HashMap<&'static str, Vec<isize>> = {
        let mut map = HashMap::new();
        
        map.insert("current_hp", vec![0xD0, 0x168]);
        map.insert("min_hp", vec![0xD0, 0x16C]);
        map.insert("max_hp", vec![0xD0, 0x170]);

        map
    };
}

pub fn get_address_path(name: &str) -> Option<&'static Vec<isize>> {
    ADDRESS_MAP.get(name)
}