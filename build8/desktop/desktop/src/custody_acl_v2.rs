//! Dedicated Desktop custody ACL. Paths are pinned by directory/file leases.
//! No protection against the current user, SYSTEM or privileged memory access.
use std::path::Path;
/// The only file names a custody lease is ever taken for, all in the one owner-and-SYSTEM
/// `WalletCustodyV2` directory: the vault and, since phase 7, the protected operation outbox and the
/// preimage store (both DPAPI-sealed record by record, see `custody_seal`).
pub const CUSTODY_FILES: [&str; 3] = [
    "wallet-hybrid-v2.sqlite",
    "operation-outbox-v1.sqlite",
    "preimages-v1.sqlite",
];
pub struct Lease {
    // Drop after SQLite closes, retaining directory/file identities throughout
    // custody. Windows share-delete is deliberately denied by every handle.
    _handles: Vec<std::fs::File>,
}
#[cfg(all(test,windows))]
mod tests {
    use super::*;
    #[test]
    fn exact_acl_hardlink_and_path_replacement_guards() {
        let mut nonce=[0;16];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let base=std::env::temp_dir().join(format!("build8-v2-acl-{}",hex::encode(nonce)));
        std::fs::create_dir(&base).unwrap();
        let directory=base.join("WalletCustodyV2");
        let path=directory.join("wallet-hybrid-v2.sqlite");
        let lease=prepare(&path).unwrap();
        assert_eq!(path.metadata().unwrap().len(),0); // no private material
        assert!(std::fs::rename(&path,directory.join("replacement.sqlite")).is_err());
        assert!(std::fs::rename(&directory,base.join("replaced")).is_err());
        let second=prepare(&path).unwrap();drop(second);drop(lease);
        let link=base.join("public-test-hardlink");
        std::fs::hard_link(&path,&link).unwrap();
        assert!(prepare(&path).is_err());
        assert_eq!(path.metadata().unwrap().len(),0);
        std::fs::remove_file(&link).unwrap();
        drop(prepare(&path).unwrap());
        std::fs::remove_file(&path).unwrap();std::fs::remove_dir(&directory).unwrap();
        // A pre-existing directory with ordinary inherited ACLs is rejected;
        // the application does not silently take over or rewrite its policy.
        std::fs::create_dir(&directory).unwrap();
        assert!(prepare(&path).is_err());assert!(!path.exists());
        assert!(prepare(&base.join("wallet-hybrid-v2.sqlite")).is_err());
        assert!(prepare(Path::new("WalletCustodyV2/wallet-hybrid-v2.sqlite")).is_err());
        // Phase 7: the outbox and the preimage store get exactly the same lease; any other name none.
        std::fs::remove_dir(&directory).unwrap();
        for name in &CUSTODY_FILES[1..] {
            let other = directory.join(name);
            let lease = prepare(&other).unwrap();
            assert_eq!(other.metadata().unwrap().len(), 0);
            assert!(std::fs::rename(&other, directory.join("replacement.sqlite")).is_err());
            drop(lease);
            std::fs::remove_file(&other).unwrap();
        }
        assert!(prepare(&directory.join("wallet-hybrid-v3.sqlite")).is_err());
        assert!(prepare(&directory.join("operation-outbox-v1.sqlite-journal")).is_err());
        assert!(!directory.join("wallet-hybrid-v3.sqlite").exists());
        std::fs::remove_dir(&directory).unwrap();std::fs::remove_dir(&base).unwrap();
    }
}
#[cfg(windows)]
pub fn prepare(path: &Path) -> Result<Lease, &'static str> {
    use std::{
        fs::{File, OpenOptions},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        os::windows::io::AsRawHandle,
        path::{Component, Prefix},
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    if !path.is_absolute()
        || !path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|name| CUSTODY_FILES.contains(&name))
    {
        return Err("Custody requires an absolute dedicated V2 path");
    }
    let directory = path.parent().ok_or("Missing custody directory")?;
    if directory.file_name().and_then(|s| s.to_str()) != Some("WalletCustodyV2") {
        return Err("Custody requires its separate WalletCustodyV2 directory");
    }
    let mut handles = Vec::new();
    let mut current = std::path::PathBuf::new();
    for component in directory.components() {
        match component {
            Component::Prefix(p)
                if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
            {
                current.push(component);
                continue;
            }
            Component::RootDir | Component::Normal(_) => current.push(component),
            _ => return Err("Unsupported custody path component"),
        }
        let last = current == directory;
        let created = if last {
            match std::fs::create_dir(&current) {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(_) => return Err("Cannot create dedicated custody directory"),
            }
        } else {
            false
        };
        let handle = File::options()
            .read(true)
            .share_mode(3)
            .custom_flags(0x02000000 | 0x00200000)
            .open(&current)
            .map_err(|_| "Cannot pin custody directory")?;
        let meta = handle
            .metadata()
            .map_err(|_| "Cannot inspect custody directory")?;
        if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 {
            return Err("Custody path must not traverse reparse points");
        }
        handles.push(handle);
        if last {
            acl(&current, true, created)?;
            if created
                && std::fs::read_dir(&current)
                    .map_err(|_| "Cannot inspect new custody directory")?
                    .next()
                    .is_some()
            {
                return Err("New custody directory unexpectedly contains files");
            }
        }
    }
    let (file, created) = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(3)
        .custom_flags(0x00200000)
        .open(path)
    {
        Ok(f) => (f, true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (
            OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(3)
                .custom_flags(0x00200000)
                .open(path)
                .map_err(|_| "Cannot pin existing custody database")?,
            false,
        ),
        Err(_) => return Err("Cannot create custody database"),
    };
    let meta = file
        .metadata()
        .map_err(|_| "Cannot inspect custody database")?;
    if !meta.is_file() || meta.file_attributes() & 0x400 != 0 {
        return Err("Custody database must be a regular file");
    }
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || info.nNumberOfLinks != 1
    {
        return Err("Custody database must have exactly one filesystem link");
    }
    acl(path, false, created)?;
    handles.push(file);
    Ok(Lease { _handles: handles })
}
/// Test-only (Order W10 evidence): the DACL of `path` as SDDL text, and this process user's SID, so
/// that a test can show which principals may open a file the stores or a crash left behind.
#[cfg(all(test, windows))]
pub(crate) fn dacl_for_test(path: &Path) -> (String, String) {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree},
        Security::Authorization::*,
        Security::*,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    unsafe fn text(p: *const u16) -> String {
        unsafe {
            let mut n = 0;
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(p, n)).unwrap()
        }
    }
    unsafe {
        let mut token = ptr::null_mut();
        assert_ne!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token), 0);
        let mut length = 0;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length);
        let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
        assert_ne!(
            GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), length, &mut length),
            0
        );
        CloseHandle(token);
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid = ptr::null_mut();
        assert_ne!(ConvertSidToStringSidW(user.User.Sid, &mut sid), 0);
        let sid_text = text(sid);
        LocalFree(sid.cast());
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut sd = ptr::null_mut();
        assert_eq!(
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            ),
            0
        );
        let mut sddl = ptr::null_mut();
        let mut sddl_length = 0;
        assert_ne!(
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                &mut sddl_length,
            ),
            0
        );
        let sddl_text = text(sddl);
        LocalFree(sddl.cast());
        LocalFree(sd);
        (sddl_text, sid_text)
    }
}
#[cfg(not(windows))]
pub fn prepare(_: &Path) -> Result<Lease, &'static str> {
    Err("Desktop V2 custody storage requires qualified Windows ACL/DPAPI")
}
#[cfg(windows)]
fn acl(path: &std::path::Path, directory: bool, create: bool) -> Result<(), &'static str> {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, LocalFree},
        Security::Authorization::*,
        Security::*,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Local(*mut std::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err("Cannot inspect current custody principal");
        }
        let _handle = Handle(token);
        let mut length = 0;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length);
        if length == 0 || length > 65536 {
            return Err("Token information bound");
        }
        let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        ) == 0
        {
            return Err("Token information failed");
        }
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid_text = ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_text) == 0 {
            return Err("Custody principal encoding failed");
        }
        let _sid = Local(sid_text.cast());
        let mut n = 0;
        while n < 256 && *sid_text.add(n) != 0 {
            n += 1;
        }
        if n == 256 {
            return Err("Custody principal bound");
        }
        let sid = String::from_utf16(std::slice::from_raw_parts(sid_text, n))
            .map_err(|_| "Custody principal encoding")?;
        let inherit = if directory { "OICI" } else { "" };
        let expected = format!("D:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;{sid})");
        let sddl: Vec<u16> = expected.encode_utf16().chain(Some(0)).collect();
        let mut sd = ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        ) == 0
        {
            return Err("Custody ACL creation failed");
        }
        let _sd = Local(sd);
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = ptr::null_mut();
        if GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) == 0
            || present == 0
            || acl.is_null()
        {
            return Err("Custody ACL invalid");
        }
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if create {
            let result = SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null_mut(),
            );
            if result != 0 {
                return Err("Owner-only custody ACL could not be applied");
            }
        }
        let mut actual_sd = ptr::null_mut();
        if GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut actual_sd,
        ) != 0
        {
            return Err("Custody ACL readback failed");
        }
        let _actual = Local(actual_sd);
        let mut text = ptr::null_mut();
        let mut length = 0;
        if ConvertSecurityDescriptorToStringSecurityDescriptorW(
            actual_sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            &mut length,
        ) == 0
            || length == 0
            || length > 2048
        {
            return Err("Custody ACL readback encoding failed");
        }
        let _text = Local(text.cast());
        let mut used=0;
        while used < length as usize && *text.add(used)!=0 {used+=1;}
        if used == length as usize {return Err("Custody ACL unterminated readback");}
        let actual = String::from_utf16(std::slice::from_raw_parts(text, used))
            .map_err(|_| "Custody ACL readback encoding")?;
        // AI records completed inheritance processing, not permission to inherit
        // future entries. P must remain present, and the two exact ACEs match.
        let normalized=actual.replacen("D:PAI(","D:P(",1);
        if normalized != expected {
            return Err("Custody ACL is not the exact protected owner/SYSTEM policy");
        }
    }
    Ok(())
}
