# Memory Box

Memory Box is a small, focused Rust library for local memory manipulation intended to help the development of DLL mods and hooks.

> **Status:** Experimental / Alpha — the crate is under development and may change. Recommended to use only in controlled environments.

---

## Goals

* Provide simple, pragmatic helpers for scanning and reading/writing memory inside the current process (DLL context).
* Keep the API minimal and explicit about unsafe operations.
* Support pattern/signature scanning with wildcard bytes, pointer chaining, RIP-relative helpers and safe wrappers for protected writes.

---

## Key concepts & types

### `scan_bytes(hay: &[u8], pattern: &[Option<u8>]) -> Option<usize>`

Searches a byte slice (`hay`) for a pattern described by `pattern` where `Some(byte)` is a match and `None` is a wildcard.

* Returns the index in `hay` where the pattern starts, or `None` if not found.
* Optimized to use fast searches when the pattern has no wildcards or is entirely wildcards.

### `ModuleContext`

Represents the current module (the process / DLL where the code runs):

* `ModuleContext::current() -> Option<Self>` — queries Windows to get the module base and size using `GetModuleHandleW` + `GetModuleInformation`.
* `pattern_scan(&self, pattern: &[Option<u8>]) -> Option<LocalPtr>` — scans the module image for the given wildcard pattern and returns a `LocalPtr` pointing to the match.

### `LocalPtr`

A small wrapper around a raw address in the current process (`usize`). Common helpers:

* `offset(&self, off: isize) -> Option<LocalPtr>` — add/subtract an offset safely (checked arithmetic).
* `read_bytes(&self, len: usize) -> Option<Vec<u8>>` — read `len` bytes from the address.
* `read_i32_le(&self) -> Option<i32>` — read a 32-bit little-endian integer.
* `dereference()` / `deref()` — read a pointer-sized value from the address and return a `LocalPtr` to that pointer. Handles 32-bit and 64-bit targets.
* `rip_relative(&self, offset_offset: isize, instruction_len: isize) -> Option<Self>` — helper for resolving RIP-relative addressing (common in x86-64): it reads a 32-bit displacement at `self + offset_offset` and returns the absolute target `self + instruction_len + disp`.
* `write_bytes(&self, data: &[u8]) -> Option<()>` — copy bytes into the address (unsafe raw memory write).
* `write_bytes_protected(&self, data: &[u8]) -> Option<()>` — temporarily changes page protection to `PAGE_READWRITE` using `VirtualProtect`, performs the write, then restores the previous protection. Useful for overwriting code pages.
* `write_f32()` / `write_f32_protected()` — convenience wrappers for writing `f32` values.
* `chain(self) -> LocalPtrChain` — start a builder-style chain to follow offsets and dereferences.

### `LocalPtrChain`

A tiny fluent API for pointer chasing:

* `offset(self, off: isize) -> Option<Self>` — add offset.
* `deref(self) -> Option<Self>` — dereference.
* `finish(self) -> LocalPtr` — get the resulting pointer.

---

## Usage examples

> All memory manipulation should be considered `unsafe`. Examples below demonstrate how the crate is intended to be used.

### Pattern scan in the current module

```rust
// pattern: Some(0xDE), Some(0xAD), None, Some(0xBE) means "DE AD ?? BE"
let pattern: &[Option<u8>] = &[Some(0xDE), Some(0xAD), None, Some(0xBE)];
if let Some(ctx) = ModuleContext::current() {
    if let Some(ptr) = ctx.pattern_scan(pattern) {
        println!("found at: 0x{:X}", ptr.address);
    }
}
```

### Read a 32-bit value behind a pointer chain

```rust
if let Some(base) = ModuleContext::current().map(|c| LocalPtr { address: c.module_base + 0x1234 }) {
    // follow: base + 0x10 -> deref -> +0x8 -> deref -> final address
    if let Some(final_ptr) = base.chain().offset(0x10).deref().offset(0x8).deref().finish() {
        if let Some(val) = final_ptr.read_i32_le() {
            println!("value = {}", val);
        }
    }
}
```

### Overwrite code bytes (temporary page-protection change)

```rust
let target = LocalPtr { address: 0x7FF6_1234_0000 };
let new_bytes: [u8; 5] = [0x90, 0x90, 0x90, 0x90, 0x90];
let ok = target.write_bytes_protected(&new_bytes);
match ok {
    Some(()) => println!("patched"),
    None => eprintln!("patch failed"),
}
```

### Real example (from this repository)

The project uses a signature pattern to find the game manager, resolves a RIP-relative pointer, then follows a chain of offsets to reach a structure containing multiple buff floats. The `apply()` function zeroes those buff values by writing `f32` `0.0` with protected writes.

```rust
pub const GAME_MANAGER_IMP: [Option<u8>; 17] = [
    Some(0x48), Some(0x8B), Some(0x05), None, None, None, None,
    Some(0x48), Some(0x8B), Some(0x58), Some(0x38), Some(0x48),
    Some(0x85), Some(0xDB), Some(0x74), None, Some(0xF6),
];

pub fn apply() -> Option<()> {
    let param_start: LocalPtr = ModuleContext::current()?
        .pattern_scan(&GAME_MANAGER_IMP)?
        .rip_relative(3, 7)?
        .deref()?
        .chain()
        .offset(0x18)?
        .deref()?
        .offset(0x310)?
        .deref()?
        .offset(0xD8)?
        .deref()?
        .offset(0x1C8)?
        .offset(0x60C)?
        .finish();

    const BUFFS: [isize; 7] = [0x254, 0x274, 0x294, 0x2B4, 0x2D4, 0x2F4, 0x3B4];

    for &off in &BUFFS {
        param_start.offset(off)?.write_f32_protected(0.0)?;
    }

    Some(())
}
```

This example demonstrates:

* Using wildcard patterns to match relative addresses inside code.
* Resolving RIP-relative pointers and following multiple dereferences.
* Applying protected writes to multiple offsets inside a structure.

---

## Platform notes

* The current implementation is Windows-specific and uses `windows_sys` to query module information and change memory protections.
* Pointer-size awareness: dereference reads 4 bytes on 32-bit targets and 8 bytes on 64-bit targets.
* `write_bytes_protected` sets protection on a single 4KB page (the implementation derives `start_page` from the target address and uses a constant page size of `0x1000`).

---

## Safety & warnings

* These helpers make direct memory accesses and are inherently unsafe. Calling code should wrap operations in `unsafe` and run only in controlled environments.
* Invalid reads/writes may crash the process or introduce undefined behaviour. Test in VMs or isolated processes.
* Use the protected write helpers when patching executable pages to avoid access violations, but be careful restoring the original protection.

---

## Development & contributing

If you want this crate to support remote processes, additional OSes, or more robust pattern engines (masks, AOB with `?` wildcards in a string form), feel free to open issues or PRs. Suggested improvements:

* Add documentation comments for each public function and type.
* Add unit tests that run in an isolated process, exercising safe read/write and pattern scanning.
* Optionally expose higher-level typed read/write helpers (e.g. `read<T>`, `write<T>`) with `bytemuck` or `unsafe` conversions.

---


## Contact

Open an issue on the repository.
