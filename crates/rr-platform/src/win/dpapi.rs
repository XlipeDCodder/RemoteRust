//! DPAPI (`CryptProtectData` / `CryptUnprotectData`), current-user scope.
#![allow(unsafe_code)] // FFI module: every block below is justified with `SAFETY:`.

use std::io;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::w;
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn protect(plain: &[u8]) -> io::Result<Vec<u8>> {
    let input = input_blob(plain)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` describes `plain`, which outlives the call and is only
    // read. `output` is a valid, writable out-parameter. No UI is allowed.
    unsafe {
        CryptProtectData(
            &input,
            w!("RustRemote secret"),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(io::Error::other)?;
    Ok(take_output(output).to_vec())
}

pub(crate) fn unprotect(blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let input = input_blob(blob)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: same contract as in `protect`; the description out-parameter is
    // not requested.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(io::Error::other)?;
    Ok(take_output(output))
}

fn input_blob(data: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "secret too large for DPAPI"))?;
    Ok(CRYPT_INTEGER_BLOB {
        cbData: len,
        // DPAPI never writes through input blobs; the cast only satisfies the C signature.
        pbData: data.as_ptr().cast_mut(),
    })
}

/// Copies a DPAPI output buffer into Rust memory, wipes it and frees it.
fn take_output(blob: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
    if blob.pbData.is_null() {
        return Zeroizing::new(Vec::new());
    }
    let len = usize::try_from(blob.cbData).unwrap_or(0);
    // SAFETY: on success DPAPI returns a `LocalAlloc` buffer of exactly
    // `cbData` bytes at `pbData`, exclusively owned by us until freed below.
    let data = unsafe { std::slice::from_raw_parts_mut(blob.pbData, len) };
    let copy = Zeroizing::new(data.to_vec());
    data.zeroize();
    // SAFETY: `pbData` was allocated by DPAPI with `LocalAlloc`, is freed
    // exactly once, and `data` is not used afterwards.
    unsafe { LocalFree(Some(HLOCAL(blob.pbData.cast()))) };
    copy
}
