//! Apply and verify custody permissions on the exact opened file handle.
#[cfg(windows)]
pub fn check(file: &std::fs::File, create: bool) -> Result<(), &'static str> {
    use std::{os::windows::io::AsRawHandle, ptr};
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
        let sddl: Vec<u16> = format!("D:P(A;;FA;;;SY)(A;;FA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
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
        if create {
            let result = SetSecurityInfo(
                file.as_raw_handle(),
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
        let mut actual_owner = ptr::null_mut();
        if GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &mut actual_owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut actual_sd,
        ) != 0
        {
            return Err("Custody ACL readback failed");
        }
        let _actual = Local(actual_sd);
        if actual_owner.is_null() || EqualSid(actual_owner, user.User.Sid) == 0 {
            return Err("Custody file must be owned by the current principal");
        }
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
        let mut used = 0;
        while used < length as usize && *text.add(used) != 0 {
            used += 1;
        }
        if used == length as usize {
            return Err("Custody ACL readback bound");
        }
        let actual = String::from_utf16(std::slice::from_raw_parts(text, used))
            .map_err(|_| "Custody ACL encoding")?;
        if actual.replacen("D:PAI(", "D:P(", 1) != format!("D:P(A;;FA;;;SY)(A;;FA;;;{sid})") {
            return Err("Custody ACL is not the exact protected owner/SYSTEM policy");
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
pub fn check(file: &std::fs::File, create: bool) -> Result<(), &'static str> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if create {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "Custody mode failed")?;
    }
    let meta = file.metadata().map_err(|_| "Custody metadata failed")?;
    if meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
    {
        return Err("Custody requires current owner,mode0600,one link");
    }
    Ok(())
}
#[cfg(not(any(windows, target_os = "linux")))]
pub fn check(_: &std::fs::File, _: bool) -> Result<(), &'static str> {
    Err("Unsupported custody platform")
}
