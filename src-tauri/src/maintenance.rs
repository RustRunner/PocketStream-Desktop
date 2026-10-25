//! Protected, fixed maintenance diagnostics. No profile or media initialization.
use std::os::windows::fs::MetadataExt;
use std::path::PathBuf;
use std::ptr::null_mut;
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree},
    Security::{
        Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        },
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

pub(crate) fn protected_root() -> Result<PathBuf, &'static str> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("Cannot inspect maintenance token");
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut size = 0;
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    };
    unsafe { CloseHandle(token) };
    if queried == 0 || elevation.TokenIsElevated == 0 {
        return Err("Administrator maintenance token required");
    }
    let image = std::env::current_exe().map_err(|_| "Executing image unavailable")?;
    for path in image.ancestors() {
        let meta =
            std::fs::symlink_metadata(path).map_err(|_| "Cannot inspect maintenance path")?;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("Reparse maintenance paths are unsupported");
        }
    }
    let root = image
        .parent()
        .ok_or("Executing image has no directory")?
        .to_path_buf();
    // Inspect the directory and executable: an inherited/custom user-write ACE
    // cannot turn an elevated maintenance entry into a writable-file surface.
    for path in [&root, &image] {
        let wide: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut sd = null_mut();
        if unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                5,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            )
        } != 0
        {
            return Err("Cannot inspect maintenance ACL");
        }
        let mut text = null_mut();
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 5, &mut text, null_mut())
        };
        unsafe { LocalFree(sd) };
        if ok == 0 {
            return Err("Cannot decode maintenance ACL");
        }
        let mut len = 0;
        while unsafe { *text.add(len) } != 0 {
            len += 1;
        }
        let descriptor = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        unsafe { LocalFree(text.cast()) };
        if !protected_descriptor(&descriptor) {
            return Err("Maintenance requires an administrator-owned image and directory without user-write grants");
        }
    }
    Ok(root)
}

fn protected_descriptor(s: &str) -> bool {
    if !(s.starts_with("O:BA") || s.starts_with("O:SY")) || !s.contains("D:") {
        return false;
    }
    let mut any = false;
    for ace in s.split('(').skip(1) {
        let Some(ace) = ace.split(')').next() else {
            return false;
        };
        let fields: Vec<_> = ace.split(';').collect();
        if fields.len() != 6 {
            return false;
        }
        if fields[0] == "D" || fields[1].contains("IO") {
            continue;
        }
        if fields[0] != "A" {
            return false;
        }
        any = true;
        let rights = fields[2];
        let writes = if let Some(hex) = rights.strip_prefix("0x") {
            u32::from_str_radix(hex, 16)
                .map(|mask| mask & 0x500d0116 != 0)
                .unwrap_or(true)
        } else {
            rights
                .as_bytes()
                .chunks(2)
                .any(|r| !matches!(r, b"FR" | b"FX" | b"GR" | b"GX" | b"RC"))
        };
        if writes && !matches!(fields[5], "BA" | "SY") {
            return false;
        }
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_diagnostics_reject_user_writes_and_user_owners() {
        assert!(protected_descriptor(
            "O:BAD:AI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;GA;;;CO)"
        ));
        for s in [
            "O:BUD:(A;;FA;;;BA)",
            "O:BAD:(A;;FW;;;BU)",
            "O:BAD:(A;;0x1301bf;;;AU)",
            "O:BAD:NO_ACCESS_CONTROL",
        ] {
            assert!(!protected_descriptor(s));
        }
    }
}
