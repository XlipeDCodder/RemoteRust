//! Windows backends: DXGI Desktop Duplication, D3D11, `SendInput`,
//! WTS session APIs, named pipes and low-level keyboard hooks.
//!
//! Named `win` (not `windows`) so it never clashes with the `windows` crate.

pub(crate) mod capture;
pub(crate) mod cursor;
pub(crate) mod dpapi;
pub(crate) mod dpi;
pub(crate) mod hook;
pub(crate) mod input;

use crate::capture::CaptureError;

/// Wraps a Windows error for `context`.
pub(crate) fn os_error(context: &'static str, err: &windows::core::Error) -> CaptureError {
    CaptureError::Os {
        context,
        code: err.code().0.cast_unsigned(),
        message: err.message(),
    }
}
