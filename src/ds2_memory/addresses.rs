use std::collections::HashMap;
use lazy_static::lazy_static;

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