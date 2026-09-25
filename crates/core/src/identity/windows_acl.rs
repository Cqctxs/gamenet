//! Apply a protected ACL before secret bytes are written to a new file.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_ALL, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW,
    TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetTokenInformation, NO_INHERITANCE,
    PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(super) fn set_owner_only(path: &Path) -> io::Result<()> {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = TokenHandle(token);
    let mut required = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) };
    if required < size_of::<TOKEN_USER>() as u32 {
        return Err(io::Error::last_os_error());
    }
    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut data = vec![0usize; words];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            data.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sid = unsafe { (*(data.as_ptr() as *const TOKEN_USER)).User.Sid };
    if sid.is_null() {
        return Err(io::Error::other("Current user SID is missing"));
    }
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: SET_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid.cast(),
        },
    };
    let mut acl: *mut ACL = ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(1, &entry, ptr::null(), &mut acl) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let acl = LocalAcl(acl);
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl.0,
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

struct TokenHandle(HANDLE);
impl Drop for TokenHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalAcl(*mut ACL);
impl Drop for LocalAcl {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0.cast()) };
    }
}
