#![allow(unused)]

use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, Module32First, Module32Next, PROCESSENTRY32, MODULEENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory, VirtualProtectEx, VirtualAllocEx, VirtualQueryEx};
use winapi::um::winnt::{PROCESS_ALL_ACCESS, HANDLE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, MEM_COMMIT, MEM_RESERVE, MEM_IMAGE, MEM_PRIVATE, MEMORY_BASIC_INFORMATION};
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::FALSE;
use std::ptr;
use std::mem;
use std::collections::HashSet;

#[derive(Debug)]
pub enum ProcessError {
    SnapshotFailed,
    ProcessNotFound,
}

pub struct Process {
    name: String,
    pid: u32,
    handle: HANDLE,
    base: usize,
    injected_size: usize,
}

impl Process {
    pub fn new(name: &str) -> Result<Self, ProcessError> {
        let pid = Self::find_process_pid(name)?;
        let mut proc = Process {
            name: name.to_string(),
            pid,
            handle: ptr::null_mut(),
            base: 0,
            injected_size: 0,
        };

        unsafe {
            proc.handle = OpenProcess(PROCESS_ALL_ACCESS - 0x1, FALSE as i32, pid);
            if proc.handle.is_null() {
                return Err(ProcessError::SnapshotFailed);
            }
        }

        proc.base = proc.get_module_base(name);
        Ok(proc)
    }

    fn find_process_pid(process_name: &str) -> Result<u32, ProcessError> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot as *mut _ == ptr::null_mut() {
                return Err(ProcessError::SnapshotFailed);
            }

            let mut entry: PROCESSENTRY32 = mem::zeroed();
            entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

            if Process32First(snapshot, &mut entry) == FALSE {
                return Err(ProcessError::SnapshotFailed);
            }

            loop {
                let exe_bytes: Vec<u8> = entry.szExeFile.iter().map(|&b| b as u8).take_while(|&b| b != 0).collect();
                let exe_name = String::from_utf8_lossy(&exe_bytes).to_string();

                if exe_name.eq_ignore_ascii_case(process_name) || exe_name.eq_ignore_ascii_case(&format!("{}.exe", process_name)) {
                    return Ok(entry.th32ProcessID);
                }

                if Process32Next(snapshot, &mut entry) == FALSE {
                    break;
                }
            }

            return Err(ProcessError::ProcessNotFound);
        }
    }

    pub fn pid(&self) -> u32 {
        return self.pid;
    }

    pub fn name(&self) -> &str {
        return &self.name;
    }

    pub fn base(&self) -> usize {
        return self.base;
    }

    pub fn handle(&self) -> HANDLE {
        return self.handle;
    }

    pub fn get_module_base(&self, module_name: &str) -> usize {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid);
            if snapshot as *mut _ == ptr::null_mut() {
                return 0;
            }

            let mut entry: MODULEENTRY32 = mem::zeroed();
            entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;

            if Module32First(snapshot, &mut entry) == FALSE {
                return 0;
            }

            loop {
                let mod_bytes: Vec<u8> = entry.szModule.iter().map(|&b| b as u8).take_while(|&b| b != 0).collect();
                let mod_name = String::from_utf8_lossy(&mod_bytes).to_string();

                if mod_name.eq_ignore_ascii_case(module_name) || mod_name.eq_ignore_ascii_case(&format!("{}.dll", module_name)) {
                    return entry.modBaseAddr as usize;
                }

                if Module32Next(snapshot, &mut entry) == FALSE {
                    break;
                }
            }

            return 0;
        }
    }

    pub fn read<T: Default + Copy>(&self, addr: usize) -> T {
        let mut value: T = T::default();
        unsafe {
            ReadProcessMemory(self.handle, addr as *const c_void, &mut value as *mut T as *mut c_void, mem::size_of::<T>(), ptr::null_mut());
        }
        return value;
    }

    pub fn write<T: Copy>(&self, addr: usize, value: T) -> bool {
        unsafe {
            return WriteProcessMemory(self.handle, addr as *mut c_void, &value as *const T as *const c_void, mem::size_of::<T>(), ptr::null_mut()) != FALSE;
        }
    }

    pub fn read_buffer(&self, addr: usize, buffer: &mut [u8]) -> bool {
        unsafe {
            return ReadProcessMemory(self.handle, addr as *const c_void, buffer.as_mut_ptr() as *mut c_void, buffer.len(), ptr::null_mut()) != FALSE;
        }
    }

    pub fn write_buffer(&self, addr: usize, buffer: &[u8]) -> bool {
        unsafe {
            let result = WriteProcessMemory(self.handle, addr as *mut c_void, buffer.as_ptr() as *const c_void, buffer.len(), ptr::null_mut());
            return result != FALSE;
        }
    }

    pub fn allocate(&self, size: usize) -> usize {
        unsafe {
            let addr = VirtualAllocEx(self.handle, ptr::null_mut(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if addr.is_null() {
                return 0;
            }
            return addr as usize;
        }
    }

    pub fn inject(&mut self, code: &[u8]) -> usize {
        let shlwapi_base = self.get_module_base("shlwapi.dll");
        if shlwapi_base == 0 {
            return 0;
        }

        let target_addr = shlwapi_base + 0x1000 + self.injected_size;
        let mut code_ = code.to_vec();
        code_.push(0x90);

        let mut old_protect = 0u32;

        unsafe {
            let result = VirtualProtectEx(self.handle, target_addr as *mut c_void, code_.len(), PAGE_EXECUTE_READWRITE, &mut old_protect as *mut u32);

            if result == FALSE {
                return 0;
            }
        }

        if !self.write_buffer(target_addr, &code_) {
            return 0;
        }

        unsafe {
            VirtualProtectEx(self.handle, target_addr as *mut c_void, code_.len(), old_protect, ptr::null_mut());
        }

        self.injected_size += code_.len();
        return target_addr;
    }

    pub fn scan(&self, target_value: u64) -> Vec<u64> {
        let mut regions = Vec::new();
        let mut found_addresses = HashSet::new();

        unsafe {
            let mut sysinfo: SYSTEM_INFO = mem::zeroed();
            GetSystemInfo(&mut sysinfo);

            let max_address = sysinfo.lpMaximumApplicationAddress as u64;
            let page_size = sysinfo.dwPageSize as u64;
            let mut address: u64 = 0;

            while address < max_address {
                let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();

                let result = VirtualQueryEx(self.handle, address as *const c_void, &mut mbi, mem::size_of::<MEMORY_BASIC_INFORMATION>());

                if result == 0 {
                    address += page_size;
                    continue;
                }

                if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_READWRITE) != 0 && mbi.RegionSize >= mem::size_of::<u64>() {

                    if mbi.RegionSize > 4096 && mbi.RegionSize < 1024 * 1024 * 1024 {
                        regions.push((mbi.BaseAddress as u64, mbi.RegionSize));
                    }
                }

                address = mbi.BaseAddress as u64 + mbi.RegionSize as u64;
            }

            for &(region_start, region_size) in &regions {
                let mut buffer = vec![0u8; region_size];
                let mut bytes_read: usize = 0;

                let result = ReadProcessMemory(
                    self.handle,
                    region_start as *const c_void,
                    buffer.as_mut_ptr() as *mut c_void,
                    region_size,
                    &mut bytes_read,
                );

                if result != FALSE as i32 as i32 && bytes_read > 0 {
                    let ptr = buffer.as_ptr();
                    let max_i = bytes_read.saturating_sub(8);

                    let mut i = 0;
                    while i <= max_i {
                        let v = *(ptr.add(i) as *const u64);
                        if v == target_value {
                            found_addresses.insert(region_start + i as u64);
                        }
                        i += 8;
                    }
                }
            }
        }

        return found_addresses.into_iter().collect();
    }
}