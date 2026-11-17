//! Per-monitor DPI awareness (blueprint v2 §8.3: "Windows processes are
//! per-monitor DPI-aware v2").
#![allow(unsafe_code)] // FFI module: every block below is justified with `SAFETY:`.

use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};

use crate::capture::CaptureError;
use crate::win::os_error;

pub(crate) fn set_per_monitor_v2() -> Result<(), CaptureError> {
    // SAFETY: plain call with a predefined context handle; it only changes
    // how this process sees coordinates.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) }
        .map_err(|err| os_error("SetProcessDpiAwarenessContext", &err))
}
