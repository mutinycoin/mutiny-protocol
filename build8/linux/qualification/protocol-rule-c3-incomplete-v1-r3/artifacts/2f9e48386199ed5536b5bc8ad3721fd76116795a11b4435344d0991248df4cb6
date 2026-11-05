//! Local archive protection. No key/custody access and no external helper process.
//! The host account and administrators remain trusted; this is not a sandbox for
//! an attacker already running as that account. Existing paths are never chmod-ed.
use super::submission_pool_v1::{PoolError, Result};
use std::{fs, path::Path};
pub(crate) fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(PoolError::Io(e)),
    }
}
pub(crate) fn real_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(PoolError::ArchiveProtection);
    }
    #[cfg(windows)]
    if !matches!(path.components().next(), Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)))
    {
        return Err(PoolError::ArchiveProtection); // local drive paths only, no UNC/device namespace.
    }
    for part in path.ancestors() {
        let meta = match fs::symlink_metadata(part) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(PoolError::Io(e)),
        };
        if meta.file_type().is_symlink() {
            return Err(PoolError::ArchiveProtection);
        }
        if meta.is_dir() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                unsafe extern "C" {
                    fn geteuid() -> u32;
                }
                // A trusted sticky directory (e.g. /tmp) cannot replace another
                // owner's existing child. Untrusted owners remain unacceptable.
                if (meta.uid() != 0 && meta.uid() != unsafe { geteuid() })
                    || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0)
                {
                    return Err(PoolError::ArchiveProtection);
                }
            }
            #[cfg(windows)]
            windows::ancestor(part)?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(PoolError::ArchiveProtection);
            }
        }
    }
    Ok(())
}
pub(crate) fn directory(path: &Path) -> Result<bool> {
    real_path(path)?;
    let created = if present(path)? {
        false
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(PoolError::Io)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(path).map_err(PoolError::Io)?;
        true
    };
    if !fs::symlink_metadata(path).map_err(PoolError::Io)?.is_dir() {
        return Err(PoolError::ArchiveProtection);
    }
    #[cfg(windows)]
    {
        if created {
            windows::protect(path)?;
        }
    }
    #[cfg(not(windows))]
    let _ = created;
    check(path, true)?;
    Ok(created)
}
pub(crate) fn check(path: &Path, directory: bool) -> Result<()> {
    real_path(path)?;
    let m = fs::symlink_metadata(path).map_err(PoolError::Io)?;
    if m.is_dir() != directory || (!directory && !m.is_file()) {
        return Err(PoolError::ArchiveProtection);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        if m.uid() != unsafe { geteuid() }
            || m.mode() & 0o077 != 0
            || (!directory && m.nlink() != 1)
        {
            return Err(PoolError::ArchiveProtection);
        }
    }
    #[cfg(windows)]
    windows::check(path, directory)?;
    #[cfg(not(any(unix, windows)))]
    return Err(PoolError::ArchiveProtection);
    Ok(())
}
pub(crate) fn same_filesystem(a: &Path, b: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::metadata(a).map_err(PoolError::Io)?.dev()
            != fs::metadata(b).map_err(PoolError::Io)?.dev()
        {
            return Err(PoolError::ArchiveProtection);
        }
    }
    #[cfg(windows)]
    if windows::volume(a)? != windows::volume(b)? {
        return Err(PoolError::ArchiveProtection);
    }
    #[cfg(not(any(unix, windows)))]
    return Err(PoolError::ArchiveProtection);
    Ok(())
}
#[cfg(windows)]
mod windows {
    use super::*;
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::null_mut};
    type Ptr = *mut c_void;
    #[repr(C)]
    struct Acl {
        revision: u8,
        reserved: u8,
        size: u16,
        count: u16,
        reserved2: u16,
    }
    #[repr(C)]
    struct Ace {
        kind: u8,
        flags: u8,
        size: u16,
        mask: u32,
        sid: u32,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: Ptr, access: u32, token: *mut Ptr) -> i32;
        fn GetTokenInformation(
            token: Ptr,
            class: u32,
            data: Ptr,
            length: u32,
            needed: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: Ptr, out: *mut *mut u16) -> i32;
        fn ConvertStringSidToSidW(raw: *const u16, out: *mut Ptr) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            raw: *const u16,
            revision: u32,
            out: *mut Ptr,
            length: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            sd: Ptr,
            present: *mut i32,
            acl: *mut *mut Acl,
            defaulted: *mut i32,
        ) -> i32;
        fn GetSecurityDescriptorControl(sd: Ptr, control: *mut u16, revision: *mut u32) -> i32;
        fn SetNamedSecurityInfoW(
            name: *mut u16,
            kind: u32,
            info: u32,
            owner: Ptr,
            group: Ptr,
            acl: *mut Acl,
            sacl: Ptr,
        ) -> u32;
        fn GetNamedSecurityInfoW(
            name: *const u16,
            kind: u32,
            info: u32,
            owner: *mut Ptr,
            group: *mut Ptr,
            acl: *mut *mut Acl,
            sacl: *mut Ptr,
            sd: *mut Ptr,
        ) -> u32;
        fn GetAce(acl: *mut Acl, index: u32, ace: *mut Ptr) -> i32;
        fn EqualSid(a: Ptr, b: Ptr) -> i32;
        fn IsValidSid(sid: Ptr) -> i32;
        fn GetLengthSid(sid: Ptr) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Ptr;
        fn CloseHandle(handle: Ptr) -> i32;
        fn LocalFree(memory: Ptr) -> Ptr;
        fn GetVolumePathNameW(file: *const u16, volume: *mut u16, length: u32) -> i32;
        fn GetVolumeNameForVolumeMountPointW(mount: *const u16, name: *mut u16, length: u32)
        -> i32;
        fn GetFileInformationByHandle(handle: Ptr, information: *mut u32) -> i32;
    }
    struct Local(Ptr);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain([0]).collect()
    }
    fn text(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }
    fn user() -> Result<(Vec<usize>, String)> {
        unsafe {
            let mut token = null_mut();
            if OpenProcessToken(GetCurrentProcess(), 8, &mut token) == 0 {
                return Err(PoolError::ArchiveProtection);
            }
            let mut length = 0;
            GetTokenInformation(token, 1, null_mut(), 0, &mut length);
            if length == 0 || length > 65536 {
                CloseHandle(token);
                return Err(PoolError::ArchiveProtection);
            }
            // usize alignment is required by TOKEN_USER's SID pointer.
            let mut data = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
            let ok = GetTokenInformation(token, 1, data.as_mut_ptr().cast(), length, &mut length);
            CloseHandle(token);
            if ok == 0 {
                return Err(PoolError::ArchiveProtection);
            }
            let sid = *(data.as_ptr() as *const Ptr);
            let mut raw = null_mut();
            if ConvertSidToStringSidW(sid, &mut raw) == 0 {
                return Err(PoolError::ArchiveProtection);
            }
            let allocation = Local(raw.cast());
            let mut n = 0;
            while *raw.add(n) != 0 {
                n += 1;
                if n > 256 {
                    return Err(PoolError::ArchiveProtection);
                }
            }
            let value = String::from_utf16(std::slice::from_raw_parts(raw, n))
                .map_err(|_| PoolError::ArchiveProtection)?;
            drop(allocation);
            Ok((data, value))
        }
    }
    pub(super) fn ancestor(path: &Path) -> Result<()> {
        let (data, _) = user()?;
        unsafe {
            let user = *(data.as_ptr() as *const Ptr);
            let mut trusted = Vec::new();
            // The Windows system service SID is the local C:\ owner, checked
            // against NT SERVICE\TrustedInstaller during implementation review.
            for value in [
                "S-1-5-18",
                "S-1-5-32-544",
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            ] {
                let mut sid = null_mut();
                if ConvertStringSidToSidW(text(value).as_ptr(), &mut sid) == 0 {
                    return Err(PoolError::ArchiveProtection);
                }
                trusted.push(Local(sid));
            }
            let is_trusted = |sid: Ptr| {
                EqualSid(sid, user) != 0 || trusted.iter().any(|t| EqualSid(sid, t.0) != 0)
            };
            let mut sd = null_mut();
            let mut owner = null_mut();
            let mut acl = null_mut();
            if GetNamedSecurityInfoW(
                wide(path.as_os_str()).as_ptr(),
                1,
                1 | 4,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut sd,
            ) != 0
            {
                return Err(PoolError::ArchiveProtection);
            }
            let _sd = Local(sd);
            if owner.is_null() || acl.is_null() || !is_trusted(owner) {
                return Err(PoolError::ArchiveProtection);
            }
            for i in 0..u32::from((*acl).count) {
                let mut raw = null_mut();
                if GetAce(acl, i, &mut raw) == 0 {
                    return Err(PoolError::ArchiveProtection);
                }
                let ace = &*(raw as *const Ace);
                if ace.flags & 8 != 0 {
                    continue;
                } // INHERIT_ONLY does not apply here.
                if ace.kind == 1 {
                    continue;
                } // A deny cannot grant replacement rights.
                if ace.kind != 0 || ace.size < 16 {
                    return Err(PoolError::ArchiveProtection);
                }
                let sid = std::ptr::addr_of!(ace.sid) as Ptr;
                if IsValidSid(sid) == 0 || GetLengthSid(sid) > u32::from(ace.size) - 8 {
                    return Err(PoolError::ArchiveProtection);
                }
                // DELETE_CHILD can replace a protected child despite its ACL.
                // DELETE can move an ancestor; WRITE_DAC/OWNER and generic writes
                // can grant replacement rights. Creation/read/traverse alone do not.
                let unsafe_mask = 0x2 // Conservatively refuse additional ancestor write rights.
                    | 0x10 // WRITE_EA
                    | 0x100 // WRITE_ATTRIBUTES
                    | 0x40
                    | 0x40000
                    | 0x80000
                    | 0x10000000
                    | 0x40000000
                    | if path.parent().is_some() { 0x10000 } else { 0 };
                if !is_trusted(sid) && ace.mask & unsafe_mask != 0 {
                    return Err(PoolError::ArchiveProtection);
                }
            }
        }
        Ok(())
    }
    pub(super) fn protect(path: &Path) -> Result<()> {
        let (_user, sid) = user()?;
        protect_descriptor(path, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})"))
    }
    #[cfg(test)]
    pub(super) fn fixture_shared(path: &Path) -> Result<()> {
        let (_user, sid) = user()?;
        protect_descriptor(
            path,
            &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})(A;OICI;FA;;;AU)"),
        )
    }
    fn protect_descriptor(path: &Path, descriptor: &str) -> Result<()> {
        let descriptor = text(descriptor);
        let mut name = wide(path.as_os_str());
        unsafe {
            let mut sd = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                1,
                &mut sd,
                null_mut(),
            ) == 0
            {
                return Err(PoolError::ArchiveProtection);
            }
            let _allocation = Local(sd);
            let mut acl = null_mut();
            let mut present = 0;
            let mut defaulted = 0;
            if GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) == 0
                || present == 0
                || acl.is_null()
            {
                return Err(PoolError::ArchiveProtection);
            }
            if SetNamedSecurityInfoW(
                name.as_mut_ptr(),
                1,
                4 | 0x80000000,
                null_mut(),
                null_mut(),
                acl,
                null_mut(),
            ) != 0
            {
                return Err(PoolError::ArchiveProtection);
            }
        }
        Ok(())
    }
    pub(super) fn check(path: &Path, directory: bool) -> Result<()> {
        if !directory {
            use std::os::windows::io::AsRawHandle;
            let file = fs::File::open(path).map_err(PoolError::Io)?;
            let mut info = [0u32; 13];
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0
                || info[10] != 1
            {
                return Err(PoolError::ArchiveProtection);
            }
        }
        let (data, _) = user()?;
        let name = wide(path.as_os_str());
        unsafe {
            let user = *(data.as_ptr() as *const Ptr);
            let mut system = null_mut();
            if ConvertStringSidToSidW(text("S-1-5-18").as_ptr(), &mut system) == 0 {
                return Err(PoolError::ArchiveProtection);
            }
            let _sys = Local(system);
            // Elevated Windows may use Administrators as the default owner.
            // No access ACE is added: only this user and SYSTEM are permitted.
            let mut administrators = null_mut();
            if ConvertStringSidToSidW(text("S-1-5-32-544").as_ptr(), &mut administrators) == 0 {
                return Err(PoolError::ArchiveProtection);
            }
            let _administrators = Local(administrators);
            let mut sd = null_mut();
            let mut owner = null_mut();
            let mut acl = null_mut();
            if GetNamedSecurityInfoW(
                name.as_ptr(),
                1,
                1 | 4,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut sd,
            ) != 0
            {
                return Err(PoolError::ArchiveProtection);
            }
            let _sd = Local(sd);
            if owner.is_null()
                || acl.is_null()
                || (EqualSid(owner, user) == 0
                    && EqualSid(owner, administrators) == 0
                    && EqualSid(owner, system) == 0)
                || (*acl).count != 2
            {
                return Err(PoolError::ArchiveProtection);
            }
            let mut control = 0;
            let mut revision = 0;
            if GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0
                || (directory && control & 0x1000 == 0)
            {
                return Err(PoolError::ArchiveProtection);
            }
            let (mut user_seen, mut system_seen) = (false, false);
            for i in 0..2 {
                let mut raw = null_mut();
                if GetAce(acl, i, &mut raw) == 0 {
                    return Err(PoolError::ArchiveProtection);
                }
                let ace = &*(raw as *const Ace);
                if ace.kind != 0 || ace.mask != 0x1f01ff || ace.flags & 8 != 0 || ace.size < 16 {
                    return Err(PoolError::ArchiveProtection);
                }
                let sid = std::ptr::addr_of!(ace.sid) as Ptr;
                if IsValidSid(sid) == 0 || GetLengthSid(sid) > u32::from(ace.size) - 8 {
                    return Err(PoolError::ArchiveProtection);
                }
                if EqualSid(sid, user) != 0 && !user_seen {
                    user_seen = true;
                } else if EqualSid(sid, system) != 0 && !system_seen {
                    system_seen = true;
                } else {
                    return Err(PoolError::ArchiveProtection);
                }
            }
            if !user_seen || !system_seen {
                return Err(PoolError::ArchiveProtection);
            }
        }
        Ok(())
    }
    pub(super) fn volume(path: &Path) -> Result<Vec<u16>> {
        let mut mount = vec![0u16; 32768];
        let mut volume = vec![0u16; 128];
        unsafe {
            if GetVolumePathNameW(
                wide(path.as_os_str()).as_ptr(),
                mount.as_mut_ptr(),
                mount.len() as u32,
            ) == 0
                || GetVolumeNameForVolumeMountPointW(
                    mount.as_ptr(),
                    volume.as_mut_ptr(),
                    volume.len() as u32,
                ) == 0
            {
                return Err(PoolError::ArchiveProtection);
            }
        }
        volume.truncate(
            volume
                .iter()
                .position(|c| *c == 0)
                .ok_or(PoolError::ArchiveProtection)?,
        );
        Ok(volume)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replaceable_ancestor_and_unsafe_existing_pool_are_refused_before_mutation() {
        let base = std::env::temp_dir().join(format!(
            "mutiny-archive-ancestor-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(directory(&base).unwrap());
        assert!(!directory(&base).unwrap());
        let shared = base.join("shared-test-only");
        fs::create_dir(&shared).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        }
        #[cfg(windows)]
        windows::fixture_shared(&shared).unwrap();
        let child = shared.join("must-not-be-created");
        assert!(matches!(
            directory(&child),
            Err(PoolError::ArchiveProtection)
        ));
        assert!(!child.exists());
        let raw = b"PUBLIC TEST-VALUE refused raw candidate";
        let candidate = shared.join("pool.sqlite");
        fs::write(&candidate, raw).unwrap();
        assert!(matches!(
            crate::submission_pool_v1::SubmissionPool::open(&candidate, [1; 32], [2; 32], 1024),
            Err(PoolError::ArchiveProtection)
        ));
        assert_eq!(fs::read(&candidate).unwrap(), raw);
        assert!(!shared.join("pool.sqlite-journal").exists());
        let unsafe_file = base.join("public-file-test-only.sqlite");
        fs::write(&unsafe_file, raw).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&unsafe_file, fs::Permissions::from_mode(0o666)).unwrap();
        }
        #[cfg(windows)]
        windows::fixture_shared(&unsafe_file).unwrap();
        assert!(matches!(
            crate::submission_pool_v1::SubmissionPool::open(&unsafe_file, [1; 32], [2; 32], 1024),
            Err(PoolError::ArchiveProtection)
        ));
        assert_eq!(fs::read(&unsafe_file).unwrap(), raw);
        assert!(!base.join("public-file-test-only.sqlite-journal").exists());
        // Success fixture alone; no pre-existing path or failed evidence deleted.
        fs::remove_file(candidate).unwrap();
        fs::remove_file(unsafe_file).unwrap();
        fs::remove_dir(shared).unwrap();
        fs::remove_dir(base).unwrap();
    }
    #[test]
    fn archive_directory_is_private_and_foreign_existing_directory_is_not_repaired() {
        let base = std::env::temp_dir().join(format!(
            "mutiny-archive-protection-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(directory(&base).unwrap());
        let protected = base.join("private");
        directory(&protected).unwrap();
        check(&protected, true).unwrap();
        let path = protected.join("test-only-file");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(&path).unwrap());
        check(&path, false).unwrap();
        let alias = protected.join("test-only-alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(
            check(&path, false),
            Err(PoolError::ArchiveProtection)
        ));
        fs::remove_file(&alias).unwrap();
        check(&path, false).unwrap();
        fs::remove_file(&path).unwrap();
        let foreign = base.join("foreign");
        fs::create_dir(&foreign).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(matches!(
            directory(&foreign),
            Err(PoolError::ArchiveProtection)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&foreign).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        // Only this successful empty TEST-VALUE fixture is removed.
        fs::remove_dir(&foreign).unwrap();
        fs::remove_dir(&protected).unwrap();
        fs::remove_dir(&base).unwrap();
    }
}
