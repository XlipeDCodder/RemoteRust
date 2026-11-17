//! The pointer on Windows (blueprint v2 §6.2): `GetCursorInfo` for the
//! position and handle, `GetIconInfo` / `GetDIBits` for the image when the
//! handle changes. The Agent is per-monitor DPI aware, so positions are
//! physical virtual-desktop pixels, as for capture and input.
#![allow(unsafe_code)] // FFI module: every block below is justified with `SAFETY:`.

use std::ffi::c_void;

use windows::Win32::Foundation::POINT;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, DeleteObject, GetDC, GetDIBits,
    GetObjectW, HBITMAP, HDC, ReleaseDC,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CURSOR_SHOWING, CURSORINFO, GetCursorInfo, GetIconInfo, HCURSOR, HICON, ICONINFO,
};

use crate::capture::CaptureError;
use crate::cursor::{self, CursorSource, Pointer, Shape};
use crate::win::os_error;

/// Largest cursor bitmap side read at all; real cursors are at most 256.
const MAX_BITMAP_SIDE: usize = 1024;

/// Follows the pointer of the interactive desktop.
pub(crate) struct GdiCursor {
    /// The handle whose image was sent last (as an address: handles are
    /// process-independent values, and this keeps the source `Send`).
    last: Option<usize>,
}

impl GdiCursor {
    pub(crate) const fn new() -> Self {
        Self { last: None }
    }
}

impl CursorSource for GdiCursor {
    fn poll(&mut self) -> Result<(Pointer, Option<Shape>), CaptureError> {
        let mut info = CURSORINFO {
            cbSize: u32::try_from(size_of::<CURSORINFO>()).unwrap_or(u32::MAX),
            ..Default::default()
        };
        // SAFETY: `info` is a valid, sized out-parameter.
        unsafe { GetCursorInfo(&raw mut info) }.map_err(|err| os_error("GetCursorInfo", &err))?;
        let POINT { x, y } = info.ptScreenPos;
        let visible = info.flags.0 & CURSOR_SHOWING.0 != 0 && !info.hCursor.is_invalid();
        let pointer = Pointer { x, y, visible };
        let handle = info.hCursor.0 as usize;
        if !visible || self.last == Some(handle) {
            return Ok((pointer, None));
        }
        let shape = read_shape(info.hCursor)?;
        self.last = Some(handle);
        Ok((pointer, shape))
    }
}

/// A GDI bitmap deleted on drop.
struct Bitmap(HBITMAP);

impl Drop for Bitmap {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: GetIconInfo created the bitmap for the caller to delete.
            let _ = unsafe { DeleteObject(self.0.into()) };
        }
    }
}

/// The screen DC, released on drop.
struct ScreenDc(HDC);

impl ScreenDc {
    fn get() -> Result<Self, CaptureError> {
        // SAFETY: no preconditions; a null result is handled.
        let dc = unsafe { GetDC(None) };
        if dc.is_invalid() {
            Err(os_error("GetDC", &windows::core::Error::from_thread()))
        } else {
            Ok(Self(dc))
        }
    }
}

impl Drop for ScreenDc {
    fn drop(&mut self) {
        // SAFETY: the DC came from GetDC(None).
        let _ = unsafe { ReleaseDC(None, self.0) };
    }
}

/// The pixels of `bitmap` as top-down 32-bit BGRA, with its size.
fn read_bits(dc: &ScreenDc, bitmap: &Bitmap) -> Result<(usize, usize, Vec<u8>), CaptureError> {
    let failed = || os_error("GetDIBits", &windows::core::Error::from_thread());
    let mut header = BITMAP::default();
    // SAFETY: `header` is a valid out-parameter of the size given.
    let got = unsafe {
        GetObjectW(
            bitmap.0.into(),
            i32::try_from(size_of::<BITMAP>()).unwrap_or(i32::MAX),
            Some((&raw mut header).cast::<c_void>()),
        )
    };
    let (Ok(width), Ok(height)) = (
        usize::try_from(header.bmWidth),
        usize::try_from(header.bmHeight),
    ) else {
        return Err(failed());
    };
    if got == 0
        || width == 0
        || height == 0
        || width > MAX_BITMAP_SIDE
        || height > 2 * MAX_BITMAP_SIDE
    {
        return Err(failed());
    }
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: u32::try_from(size_of::<BITMAPINFOHEADER>()).unwrap_or(u32::MAX),
            biWidth: header.bmWidth,
            // Negative: top-down rows.
            biHeight: -header.bmHeight,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut pixels = vec![0u8; width * height * 4];
    let lines = u32::try_from(height).unwrap_or(0);
    // SAFETY: `pixels` holds `height` rows of `width` 32-bit pixels, as
    // `info` describes; the bitmap is not selected into any DC.
    let copied = unsafe {
        GetDIBits(
            dc.0,
            bitmap.0,
            0,
            lines,
            Some(pixels.as_mut_ptr().cast::<c_void>()),
            &raw mut info,
            DIB_RGB_COLORS,
        )
    };
    if u32::try_from(copied).ok() == Some(lines) {
        Ok((width, height, pixels))
    } else {
        Err(failed())
    }
}

/// The image of `cursor`; `None` when it cannot be expressed.
fn read_shape(cursor: HCURSOR) -> Result<Option<Shape>, CaptureError> {
    let mut info = ICONINFO::default();
    // SAFETY: `info` is a valid out-parameter; a stale handle makes the
    // call fail.
    unsafe { GetIconInfo(HICON(cursor.0), &raw mut info) }
        .map_err(|err| os_error("GetIconInfo", &err))?;
    let (mask, color) = (Bitmap(info.hbmMask), Bitmap(info.hbmColor));
    let hot = (info.xHotspot, info.yHotspot);
    let dc = ScreenDc::get()?;
    let (width, mask_height, mask_bits) = read_bits(&dc, &mask)?;
    if color.0.is_invalid() {
        // Monochrome: AND and XOR masks stacked in one bitmap.
        let height = mask_height / 2;
        let rgba = cursor::from_monochrome(&mask_bits, width, height);
        return Ok(Shape::new(width, height, hot, &rgba));
    }
    let (color_width, height, bgra) = read_bits(&dc, &color)?;
    if color_width != width || height != mask_height {
        return Ok(None);
    }
    Ok(Shape::new(
        width,
        height,
        hot,
        &cursor::from_color(&bgra, &mask_bits),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs an interactive desktop (not a service session).
    #[test]
    #[ignore = "needs an interactive desktop"]
    fn reads_the_current_pointer() {
        let mut source = GdiCursor::new();
        let (_, shape) = source.poll().unwrap();
        if let Some(shape) = shape {
            assert!(shape.width > 0 && shape.height > 0);
            assert_eq!(
                shape.rgba.len(),
                usize::from(shape.width) * usize::from(shape.height) * 4
            );
            assert!(shape.hot_x < shape.width && shape.hot_y < shape.height);
            // Some pixel is visible.
            assert!(shape.rgba.as_chunks::<4>().0.iter().any(|&[.., a]| a != 0));
        }
    }
}
