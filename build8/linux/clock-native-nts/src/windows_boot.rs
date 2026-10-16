//! Diagnostic only: version-pinned Windows kernel boot environment query.
//! Not an ElapsedSource, protected continuity proof or production qualification.
//! NtQuerySystemInformation is an internal, changeable API. Unsupported builds,
//! exports, layouts and nonzero status refuse without substitutes or DLL loading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootEnvironment {
    pub identifier_bytes: [u8; 16],
    pub firmware_type: u32,
    pub boot_flags: u64,
    pub os_build: u32,
}
#[cfg(all(windows, target_arch = "x86_64"))]
mod native {
    use super::BootEnvironment;
    use std::{
        ffi::{c_char, c_void},
        io,
        mem::size_of,
    };
    #[repr(C)]
    struct Version {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        service_pack: [u16; 128],
    }
    #[repr(C)]
    struct Environment {
        identifier: [u8; 16],
        firmware: u32,
        padding: u32,
        flags: u64,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    }
    type GetVersion = unsafe extern "system" fn(*mut Version) -> i32;
    type Query = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
    fn refusal(message: &str) -> io::Error {
        io::Error::other(message)
    }
    pub fn read() -> io::Result<BootEnvironment> {
        if size_of::<Version>() != 276 || size_of::<Environment>() != 32 {
            return Err(refusal("unsupported diagnostic ABI layout"));
        }
        let mut directory = [0u16; 32768];
        // SAFETY: initialized exclusive buffer and actual declared capacity.
        let length = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
        if length == 0 || length as usize >= directory.len() {
            return Err(refusal("system directory unavailable"));
        }
        let mut name = directory[..length as usize].to_vec();
        name.extend("\\ntdll.dll\0".encode_utf16());
        // SAFETY: full OS-supplied NUL-terminated path; obtain only an existing loaded module.
        let module = unsafe { GetModuleHandleW(name.as_ptr()) };
        if module.is_null() {
            return Err(refusal("system ntdll unavailable"));
        }
        // SAFETY: fixed names, no caller-selected exports or function pointers.
        let (version, query) = unsafe {
            (
                GetProcAddress(module, c"RtlGetVersion".as_ptr()),
                GetProcAddress(module, c"NtQuerySystemInformation".as_ptr()),
            )
        };
        if version.is_null() || query.is_null() {
            return Err(refusal("diagnostic exports unavailable"));
        }
        // SAFETY: version-pinned ABI; unsupported status/version/layout refuses. No
        // import library assumption or caller-controlled DLL search path is used.
        let version: GetVersion = unsafe { std::mem::transmute(version) };
        let query: Query = unsafe { std::mem::transmute(query) };
        let mut v = Version {
            size: 276,
            major: 0,
            minor: 0,
            build: 0,
            platform: 0,
            service_pack: [0; 128],
        };
        if unsafe { version(&mut v) } != 0
            || (v.major, v.minor, v.build, v.platform) != (10, 0, 26200, 2)
        {
            return Err(refusal("unreviewed Windows diagnostic build"));
        }
        let mut result = Environment {
            identifier: [0; 16],
            firmware: 0,
            padding: 0,
            flags: 0,
        };
        let mut returned = 0u32;
        // SAFETY: exact initialized 32-byte ABI buffer and separate u32 length.
        // Class90/layout is an explicitly unqualified internal-ABI hypothesis;
        // this standalone diagnostic never supplies voting or restart authority.
        if unsafe {
            query(
                90,
                (&mut result as *mut Environment).cast(),
                32,
                &mut returned,
            )
        } != 0
            || returned != 32
            || result.identifier == [0; 16]
            || !(1..=2).contains(&result.firmware)
        {
            return Err(refusal("boot environment diagnostic refused"));
        }
        Ok(BootEnvironment {
            identifier_bytes: result.identifier,
            firmware_type: result.firmware,
            boot_flags: result.flags,
            os_build: v.build,
        })
    }
}
pub fn read() -> std::io::Result<BootEnvironment> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        native::read()
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        Err(std::io::Error::other(
            "diagnostic unavailable on this target",
        ))
    }
}
#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(windows, target_arch = "x86_64"))]
    fn repeated_kernel_queries_are_nonzero_and_stable_within_this_process() {
        let first = super::read().expect("actual pinned-build kernel diagnostic");
        for _ in 0..8 {
            assert_eq!(super::read().unwrap(), first);
        }
        assert_ne!(first.identifier_bytes, [0; 16]);
        // This is not proof of cross-process/reboot/hibernate stability or protection.
    }
    #[test]
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    fn unsupported_target_has_no_random_or_wall_time_fallback() {
        assert!(super::read().is_err());
    }
}
