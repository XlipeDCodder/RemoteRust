//! Planar YUV 4:2:0 (I420) pictures and BGRA→I420 conversion
//! (blueprint v2 §8.1, §8.5).
//!
//! Color: BT.709 matrix, limited ("TV") range, the convention both the
//! encoder's VUI and the Viewer shader use. Chroma is the average of each
//! 2×2 block.

use crate::MediaError;

/// An I420 picture with tightly packed planes (stride = width).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct I420 {
    width: usize,
    height: usize,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
}

impl I420 {
    /// A black picture. Width and height must be even and non-zero.
    ///
    /// # Errors
    /// [`MediaError::BadDimensions`].
    pub fn new(width: usize, height: usize) -> Result<Self, MediaError> {
        let mut picture = Self::default();
        picture.resize(width, height)?;
        Ok(picture)
    }

    /// Changes the size, reusing the allocations. Contents become black
    /// only where planes grew.
    ///
    /// # Errors
    /// [`MediaError::BadDimensions`].
    pub fn resize(&mut self, width: usize, height: usize) -> Result<(), MediaError> {
        if width == 0 || height == 0 || !width.is_multiple_of(2) || !height.is_multiple_of(2) {
            return Err(MediaError::BadDimensions { width, height });
        }
        let luma = width
            .checked_mul(height)
            .ok_or(MediaError::BadDimensions { width, height })?;
        let chroma = luma / 4;
        self.width = width;
        self.height = height;
        self.y.resize(luma, 16);
        self.u.resize(chroma, 128);
        self.v.resize(chroma, 128);
        Ok(())
    }

    /// Width in pixels.
    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    /// Height in pixels.
    #[must_use]
    pub const fn height(&self) -> usize {
        self.height
    }

    /// Luma plane, `width × height`.
    #[must_use]
    pub fn y(&self) -> &[u8] {
        &self.y
    }

    /// Cb plane, `width/2 × height/2`.
    #[must_use]
    pub fn u(&self) -> &[u8] {
        &self.u
    }

    /// Cr plane, `width/2 × height/2`.
    #[must_use]
    pub fn v(&self) -> &[u8] {
        &self.v
    }

    /// All three planes, mutably.
    pub fn planes_mut(&mut self) -> (&mut [u8], &mut [u8], &mut [u8]) {
        (&mut self.y, &mut self.u, &mut self.v)
    }

    /// Copies planes with arbitrary strides into this picture, resizing it.
    ///
    /// # Errors
    /// [`MediaError::BadDimensions`] or [`MediaError::BadLayout`] if a
    /// plane is shorter than its strides imply.
    pub fn copy_from_planes(
        &mut self,
        width: usize,
        height: usize,
        planes: [(&[u8], usize); 3],
    ) -> Result<(), MediaError> {
        self.resize(width, height)?;
        let [(y, y_stride), (u, u_stride), (v, v_stride)] = planes;
        copy_plane(y, y_stride, &mut self.y, width, height)?;
        copy_plane(u, u_stride, &mut self.u, width / 2, height / 2)?;
        copy_plane(v, v_stride, &mut self.v, width / 2, height / 2)?;
        Ok(())
    }
}

fn copy_plane(
    src: &[u8],
    stride: usize,
    dst: &mut [u8],
    width: usize,
    height: usize,
) -> Result<(), MediaError> {
    if stride < width {
        return Err(MediaError::BadLayout("stride shorter than a row"));
    }
    let needed = stride
        .checked_mul(height.saturating_sub(1))
        .and_then(|rows| rows.checked_add(width))
        .ok_or(MediaError::BadLayout("plane size overflows"))?;
    if src.len() < needed {
        return Err(MediaError::BadLayout("plane shorter than its size"));
    }
    for (dst_row, src_row) in dst.chunks_exact_mut(width).zip(src.chunks(stride)) {
        let src_row = src_row
            .get(..width)
            .ok_or(MediaError::BadLayout("row shorter than the width"))?;
        dst_row.copy_from_slice(src_row);
    }
    Ok(())
}

/// Converts a BGRA image to I420, cropping to even dimensions.
///
/// `stride` is the byte distance between rows (≥ `width * 4`). `dst` is
/// resized as needed.
///
/// # Errors
/// [`MediaError::BadDimensions`] for an image smaller than 2×2, or
/// [`MediaError::BadLayout`] if `bgra` is too short for its geometry.
pub fn bgra_to_i420(
    bgra: &[u8],
    stride: usize,
    width: usize,
    height: usize,
    dst: &mut I420,
) -> Result<(), MediaError> {
    let width = width & !1;
    let height = height & !1;
    dst.resize(width, height)?;
    let row_bytes = width
        .checked_mul(4)
        .ok_or(MediaError::BadLayout("row size overflows"))?;
    if stride < row_bytes {
        return Err(MediaError::BadLayout("stride shorter than a row"));
    }
    let needed = stride
        .checked_mul(height - 1)
        .and_then(|rows| rows.checked_add(row_bytes))
        .ok_or(MediaError::BadLayout("image size overflows"))?;
    if bgra.len() < needed {
        return Err(MediaError::BadLayout("image shorter than its size"));
    }

    let chroma_width = width / 2;
    let (y_plane, u_plane, v_plane) = dst.planes_mut();
    let src_pairs = bgra.chunks(stride.saturating_mul(2));
    let y_pairs = y_plane.chunks_exact_mut(width.saturating_mul(2));
    let chroma_rows = u_plane
        .chunks_exact_mut(chroma_width)
        .zip(v_plane.chunks_exact_mut(chroma_width));
    for ((src, y_pair), (u_row, v_row)) in src_pairs.zip(y_pairs).zip(chroma_rows) {
        let (top, bottom) = src.split_at(stride.min(src.len()));
        let top = top
            .get(..row_bytes)
            .ok_or(MediaError::BadLayout("short row"))?;
        let bottom = bottom
            .get(..row_bytes)
            .ok_or(MediaError::BadLayout("short row"))?;
        let (y_top, y_bottom) = y_pair.split_at_mut(width);
        convert_row_pair(top, bottom, y_top, y_bottom, u_row, v_row);
    }
    Ok(())
}

// Fixed-point BT.709 limited range, 8 fractional bits:
//   Y  = 16  + ( 47 R + 157 G +  16 B) / 256
//   Cb = 128 + (-26 R -  86 G + 112 B) / 256
//   Cr = 128 + (112 R - 102 G -  10 B) / 256
// The coefficient rows sum to 220 (≈ 219), 0 and 0, so white maps to
// Y = 235 and grays carry no chroma. Inputs are bytes, so every
// intermediate stays within ±2^17: no overflow is possible.
#[allow(clippy::arithmetic_side_effects)]
#[inline]
fn luma(b: u8, g: u8, r: u8) -> u8 {
    let (r, g, b) = (i32::from(r), i32::from(g), i32::from(b));
    clamp_u8(16 + ((47 * r + 157 * g + 16 * b + 128) >> 8))
}

#[allow(clippy::arithmetic_side_effects)]
#[inline]
fn chroma(b: i32, g: i32, r: i32) -> (u8, u8) {
    // Inputs are sums of four pixels; the extra 2 bits are shifted out.
    let cb = 128 + ((-26 * r - 86 * g + 112 * b + 512) >> 10);
    let cr = 128 + ((112 * r - 102 * g - 10 * b + 512) >> 10);
    (clamp_u8(cb), clamp_u8(cr))
}

#[inline]
fn clamp_u8(value: i32) -> u8 {
    u8::try_from(value.clamp(0, 255)).unwrap_or(u8::MAX)
}

#[allow(clippy::arithmetic_side_effects)]
fn convert_row_pair(
    top: &[u8],
    bottom: &[u8],
    y_top: &mut [u8],
    y_bottom: &mut [u8],
    u_row: &mut [u8],
    v_row: &mut [u8],
) {
    // Two pixels (8 bytes) per row and two luma samples per row at a time.
    let pixels = top
        .as_chunks::<8>()
        .0
        .iter()
        .zip(bottom.as_chunks::<8>().0)
        .zip(
            y_top
                .as_chunks_mut::<2>()
                .0
                .iter_mut()
                .zip(y_bottom.as_chunks_mut::<2>().0),
        )
        .zip(u_row.iter_mut().zip(v_row.iter_mut()));
    for (((t, b), ([y0, y1], [y2, y3])), (u, v)) in pixels {
        let [b0, g0, r0, _, b1, g1, r1, _] = *t;
        let [b2, g2, r2, _, b3, g3, r3, _] = *b;
        *y0 = luma(b0, g0, r0);
        *y1 = luma(b1, g1, r1);
        *y2 = luma(b2, g2, r2);
        *y3 = luma(b3, g3, r3);
        let sum =
            |a: u8, b: u8, c: u8, d: u8| i32::from(a) + i32::from(b) + i32::from(c) + i32::from(d);
        let (cb, cr) = chroma(
            sum(b0, b1, b2, b3),
            sum(g0, g1, g2, g3),
            sum(r0, r1, r2, r3),
        );
        *u = cb;
        *v = cr;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(width: usize, height: usize, bgra: [u8; 4]) -> Vec<u8> {
        bgra.repeat(width * height)
    }

    #[test]
    fn reference_colors_convert_to_bt709_limited_range() {
        let cases = [
            ([0, 0, 0, 255], (16, 128, 128)),
            ([255, 255, 255, 255], (235, 128, 128)),
            ([128, 128, 128, 255], (126, 128, 128)),
            // Pure red, green and blue (BGRA order), ±1 for rounding.
            ([0, 0, 255, 255], (63, 102, 240)),
            ([0, 255, 0, 255], (173, 42, 26)),
            ([255, 0, 0, 255], (32, 240, 118)),
        ];
        let mut out = I420::default();
        for (pixel, (y, u, v)) in cases {
            let image = solid(4, 2, pixel);
            bgra_to_i420(&image, 16, 4, 2, &mut out).unwrap();
            let close = |got: u8, want: u8| got.abs_diff(want) <= 1;
            assert!(close(out.y()[0], y), "{pixel:?}: y {} vs {y}", out.y()[0]);
            assert!(close(out.u()[0], u), "{pixel:?}: u {} vs {u}", out.u()[0]);
            assert!(close(out.v()[0], v), "{pixel:?}: v {} vs {v}", out.v()[0]);
        }
    }

    #[test]
    fn odd_sizes_are_cropped_and_strides_respected() {
        // 5×3 image with a padded stride: becomes 4×2.
        let stride = 5 * 4 + 12;
        let mut image = vec![0u8; stride * 3];
        for row in image.chunks_mut(stride) {
            row[..20].copy_from_slice(&[255; 20]);
        }
        let mut out = I420::default();
        bgra_to_i420(&image, stride, 5, 3, &mut out).unwrap();
        assert_eq!((out.width(), out.height()), (4, 2));
        assert!(out.y().iter().all(|&y| y == 235));
        assert_eq!(out.u().len(), 2);
    }

    #[test]
    fn short_or_tiny_inputs_are_errors() {
        let mut out = I420::default();
        assert!(bgra_to_i420(&[0; 15], 8, 2, 2, &mut out).is_err());
        assert!(bgra_to_i420(&[0; 64], 4, 2, 2, &mut out).is_err());
        assert!(bgra_to_i420(&[0; 64], 8, 1, 1, &mut out).is_err());
        assert!(I420::new(3, 2).is_err());
    }

    #[test]
    fn copy_from_planes_removes_padding() {
        let y = [1u8, 2, 0, 0, 3, 4, 0, 0];
        let mut out = I420::default();
        out.copy_from_planes(2, 2, [(&y, 4), (&[5, 0], 2), (&[6], 1)])
            .unwrap();
        assert_eq!(out.y(), &[1, 2, 3, 4]);
        assert_eq!(out.u(), &[5]);
        assert_eq!(out.v(), &[6]);
        assert!(
            out.copy_from_planes(2, 2, [(&y[..5], 4), (&[5], 1), (&[6], 1)])
                .is_err()
        );
    }
}
