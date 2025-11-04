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

    let fc_idx: usize = pattern
        .iter()
        .position(|p: &Option<u8>| p.is_some())
        .unwrap();
    let fc_byte: u8 = pattern[fc_idx].unwrap();
    let max_start: usize = hay.len().saturating_sub(plen);
    let search_end: usize = fc_idx.saturating_add(max_start).saturating_add(1);
    let search_area: &[u8] = &hay[fc_idx..search_end];

    for rel in memchr_iter(fc_byte, search_area) {
        let start: usize = rel;

        let base_idx: usize = start;
        let mut ok: bool = true;
        for j in 0..plen {
            match pattern[j] {
                Some(b) => {
                    if hay[base_idx + j] != b {
                        ok = false;
                        break;
                    }
                }
                None => {}
            }
        }
        if ok {
            return Some(base_idx);
        }
    }

    None
}
