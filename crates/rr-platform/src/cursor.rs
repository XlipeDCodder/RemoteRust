//! The Agent's mouse pointer (blueprint v2 §6.2): where it is and what it
//! looks like, so the Viewer can draw it locally without waiting for video.
//!
//! Sources are polled (the Agent does it about 60 times a second). The
//! backends are `GetCursorInfo` on Windows and XFixes on X11. On Wayland
//! the portal draws the pointer into the video, so there is no source.

use crate::capture::CaptureError;

/// Largest cursor side the protocol carries; bigger shapes are cut.
pub const MAX_SIDE: usize = 256;

/// Where the pointer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pointer {
    /// Desktop position, in the coordinates of [`crate::input::Area`].
    pub x: i32,
    /// Desktop position, in the coordinates of [`crate::input::Area`].
    pub y: i32,
    /// `false` while the system hides the pointer (e.g. while typing).
    pub visible: bool,
}

/// What the pointer looks like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    /// Width in pixels, 1 to [`MAX_SIDE`].
    pub width: u16,
    /// Height in pixels, 1 to [`MAX_SIDE`].
    pub height: u16,
    /// The pixel that points, inside the shape.
    pub hot_x: u16,
    /// The pixel that points, inside the shape.
    pub hot_y: u16,
    /// Straight (not premultiplied) RGBA, `width * height * 4` bytes.
    pub rgba: Vec<u8>,
}

impl Shape {
    /// A shape from RGBA rows of `width` pixels. Shapes larger than
    /// [`MAX_SIDE`] keep their top-left part, and the hot spot is moved
    /// inside if needed. `None` for an empty or inconsistent image.
    pub(crate) fn new(width: usize, height: usize, hot: (u32, u32), rgba: &[u8]) -> Option<Self> {
        if width == 0 || height == 0 || rgba.len() != width.checked_mul(height)?.checked_mul(4)? {
            return None;
        }
        let (cut_width, cut_height) = (width.min(MAX_SIDE), height.min(MAX_SIDE));
        let pixels = rgba
            .chunks_exact(width * 4)
            .take(cut_height)
            .flat_map(|row| row.iter().take(cut_width * 4).copied())
            .collect();
        let inside = |hot: u32, side: usize| {
            let last = u16::try_from(side - 1).unwrap_or(u16::MAX);
            u16::try_from(hot).unwrap_or(u16::MAX).min(last)
        };
        Some(Self {
            width: u16::try_from(cut_width).ok()?,
            height: u16::try_from(cut_height).ok()?,
            hot_x: inside(hot.0, cut_width),
            hot_y: inside(hot.1, cut_height),
            rgba: pixels,
        })
    }
}

/// A pointer to follow.
pub trait CursorSource: Send {
    /// Where the pointer is now, plus its shape when that changed since
    /// the previous call (always on the first one).
    ///
    /// # Errors
    /// An OS failure, e.g. while the secure desktop is shown; calling again
    /// later may succeed.
    fn poll(&mut self) -> Result<(Pointer, Option<Shape>), CaptureError>;
}

/// Opens the pointer of this desktop. `Ok(None)` when the pointer is part
/// of the video instead (Wayland portal).
///
/// # Errors
/// [`CaptureError::Unsupported`] or an OS failure.
pub fn open() -> Result<Option<Box<dyn CursorSource>>, CaptureError> {
    #[cfg(windows)]
    {
        Ok(Some(Box::new(crate::win::cursor::GdiCursor::new())))
    }
    #[cfg(target_os = "linux")]
    {
        use crate::linux::{Backend, backend, x11_cursor};
        match backend()? {
            Backend::X11 => Ok(Some(Box::new(x11_cursor::XFixesCursor::open()?))),
            Backend::Portal => Ok(None),
        }
    }
}

/// Whether a 32-bit mask pixel (as `GetDIBits` returns a 1-bit bitmap) is
/// set (white).
#[cfg_attr(not(windows), allow(dead_code))]
fn is_set(pixel: &[u8; 4]) -> bool {
    let [b, g, r, _] = *pixel;
    b != 0 || g != 0 || r != 0
}

/// RGBA from a Windows color cursor: BGRA pixels and the AND mask as
/// 32-bit pixels. The mask decides transparency only when the color image
/// has no alpha channel (all zero).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn from_color(bgra: &[u8], mask: &[u8]) -> Vec<u8> {
    let (pixels, _) = bgra.as_chunks::<4>();
    let has_alpha = pixels.iter().any(|&[_, _, _, a]| a != 0);
    let mut masks = mask.as_chunks::<4>().0.iter();
    pixels
        .iter()
        .flat_map(|&[b, g, r, a]| {
            let transparent = masks.next().is_some_and(is_set);
            let alpha = if has_alpha {
                a
            } else if transparent {
                0
            } else {
                255
            };
            [r, g, b, alpha]
        })
        .collect()
}

/// RGBA from a Windows monochrome cursor: the mask bitmap as 32-bit pixels,
/// `width` × `2 * height`, AND mask on top and XOR mask below.
///
/// AND 0 / XOR 0 is black, AND 0 / XOR 1 white, AND 1 / XOR 0 transparent
/// and AND 1 / XOR 1 inverts the screen. Inverting cannot be expressed in
/// RGBA, so those pixels become black with a white outline, which shows on
/// any background (the text I-beam is drawn this way).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn from_monochrome(bits: &[u8], width: usize, height: usize) -> Vec<u8> {
    const BLACK: [u8; 4] = [0, 0, 0, 255];
    const WHITE: [u8; 4] = [255, 255, 255, 255];
    let count = width * height;
    let (words, _) = bits.as_chunks::<4>();
    let bit = |index: usize| words.get(index).is_some_and(is_set);
    let mut rgba = vec![0u8; count * 4];
    let (pixels, _) = rgba.as_chunks_mut::<4>();
    let mut inverted = Vec::new();
    for (index, pixel) in pixels.iter_mut().enumerate() {
        let color = match (bit(index), bit(count + index)) {
            (false, false) => BLACK,
            (false, true) => WHITE,
            (true, false) => continue,
            (true, true) => {
                inverted.push(index);
                BLACK
            }
        };
        *pixel = color;
    }
    for index in inverted {
        let (x, y) = (index % width, index / width);
        for ny in y.saturating_sub(1)..=(y + 1).min(height - 1) {
            for nx in x.saturating_sub(1)..=(x + 1).min(width - 1) {
                if let Some(pixel) = pixels.get_mut(ny * width + nx)
                    && pixel[3] == 0
                {
                    *pixel = WHITE;
                }
            }
        }
    }
    rgba
}

/// Straight RGBA from premultiplied ARGB words (XFixes cursor images).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn from_premultiplied_argb(pixels: &[u32]) -> Vec<u8> {
    pixels
        .iter()
        .flat_map(|&pixel| {
            let [a, r, g, b] = pixel.to_be_bytes();
            if a == 0 {
                return [0; 4];
            }
            let straight =
                |c: u8| u8::try_from(u16::from(c) * 255 / u16::from(a)).unwrap_or(u8::MAX);
            [straight(r), straight(g), straight(b), a]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_are_cut_to_the_protocol_limit() {
        let rgba = vec![7u8; 300 * 2 * 4];
        let shape = Shape::new(300, 2, (299, 5), &rgba).unwrap();
        assert_eq!((shape.width, shape.height), (256, 2));
        assert_eq!((shape.hot_x, shape.hot_y), (255, 1));
        assert_eq!(shape.rgba.len(), 256 * 2 * 4);
        assert!(Shape::new(0, 2, (0, 0), &[]).is_none());
        assert!(Shape::new(2, 2, (0, 0), &[0; 15]).is_none());
    }

    #[test]
    fn color_cursors_use_alpha_or_the_mask() {
        // BGRA with alpha: kept as is (channels swapped to RGBA).
        assert_eq!(from_color(&[1, 2, 3, 128], &[255; 4]), [3, 2, 1, 128]);
        // No alpha anywhere: white mask pixels are transparent.
        let bgra = [1, 2, 3, 0, 4, 5, 6, 0];
        let mask = [255, 255, 255, 0, 0, 0, 0, 0];
        assert_eq!(from_color(&bgra, &mask), [3, 2, 1, 0, 6, 5, 4, 255]);
    }

    #[test]
    fn monochrome_cursors_follow_and_xor() {
        const SET: [u8; 4] = [255, 255, 255, 0];
        const CLEAR: [u8; 4] = [0; 4];
        // 4 × 1: black, white, transparent, inverted; AND row then XOR row.
        let bits = [CLEAR, CLEAR, SET, SET, CLEAR, SET, CLEAR, SET].concat();
        let rgba = from_monochrome(&bits, 4, 1);
        assert_eq!(
            rgba,
            [
                0, 0, 0, 255, // black
                255, 255, 255, 255, // white
                255, 255, 255, 255, // transparent, outlined next to the inverted pixel
                0, 0, 0, 255, // inverted: black
            ]
        );
    }

    #[test]
    fn premultiplied_pixels_are_made_straight() {
        assert_eq!(from_premultiplied_argb(&[0x8040_2000]), [127, 63, 0, 128]);
        assert_eq!(from_premultiplied_argb(&[0x00FF_FFFF]), [0, 0, 0, 0]);
        assert_eq!(
            from_premultiplied_argb(&[0xFF10_2030]),
            [0x10, 0x20, 0x30, 0xFF]
        );
    }
}
