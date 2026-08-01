mod process;
use process::Process;
use std::io::Read;

#[repr(C)]
pub struct shared_memory {
    pub enabled: bool,
    pub lua_pushnumber: usize,
    pub old: usize,
}

mod offsets {
    pub static OLD: usize = 0x1D7EE50;
    pub static LUA_PUSHNUMBER: usize = 0x4B63490;
}

fn main() {
    let mut process = Process::new("RobloxPlayerBeta.exe").unwrap_or_else(|err| { eprintln!("failed to find process: {:?}.", err); eprintln!("press enter to exit..."); std::io::stdin().bytes().next(); std::process::exit(1); });

    let shared = process.allocate(std::mem::size_of::<shared_memory>());
    if shared == 0 {
        eprintln!("failed to allocate shared memory.");
        eprintln!("press enter to exit...");
        std::io::stdin().bytes().next();
        std::process::exit(1);
    }

    let mut module = include_bytes!("module.bin").to_vec();
    for i in 0..module.len().saturating_sub(8) {
        if &module[i..i + 8] == 0x1151721933u64.to_le_bytes() {
            module[i..i + 8].copy_from_slice(&(shared as u64).to_le_bytes());
            break;
        }
    }

    let old = process.base() + offsets::OLD;
    process.write_buffer(shared, unsafe {std::slice::from_raw_parts(&shared_memory {
        enabled: true,
        lua_pushnumber: process.base() + offsets::LUA_PUSHNUMBER,
        old: old + 0x67,
    } as *const _ as *const u8, std::mem::size_of::<shared_memory>())});

    let addr = process.inject(&module);
    println!("injected: 0x{:x}", addr);

    let addrs = process.scan(old as u64);
    for addr_ in addrs {
        process.write::<u64>(addr_ as usize, addr as u64);
        println!("ref: 0x{:x}", addr_);
    }

    eprintln!("press enter to exit...");
    std::io::stdin().bytes().next();
    process.write::<bool>(shared, false);
}
