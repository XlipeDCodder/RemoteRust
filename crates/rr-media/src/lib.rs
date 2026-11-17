//! RustRemote media pipeline (blueprint v2 §8).
//!
//! Responsibilities:
//! - color conversion (BGRA → I420, BT.709 limited range);
//! - encoder/decoder traits with an `openh264` backend (software, M2);
//!   FFmpeg hardware backends (NVENC, AMF, QSV, VA-API, Media Foundation)
//!   and runtime probing come next;
//! - the "latest frame wins" mailbox; adaptive rate control later (M6).
//!
//! `unsafe_code` is denied at the workspace level. The future FFmpeg wrapper
//! module is the only place allowed to opt out, with `#[allow(unsafe_code)]`
//! on that module and a `// SAFETY:` comment on every block.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

pub mod h264;
pub mod mailbox;
pub mod yuv;

pub use h264::{OpenH264Decoder, OpenH264Encoder};
pub use mailbox::Mailbox;
pub use yuv::{I420, bgra_to_i420};

/// Media errors.
#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    /// Width or height is zero, odd or too large.
    #[error("unsupported picture size {width}x{height}")]
    BadDimensions {
        /// Requested width.
        width: usize,
        /// Requested height.
        height: usize,
    },
    /// A buffer does not match its declared geometry.
    #[error("bad buffer layout: {0}")]
    BadLayout(&'static str),
    /// The codec library reported an error.
    #[error("codec error: {0}")]
    Codec(String),
}

/// Encoder parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderSettings {
    /// Target bitrate in bits per second.
    pub bitrate_bps: u32,
    /// Highest frame rate the encoder should expect.
    pub max_fps: u8,
}

impl Default for EncoderSettings {
    /// 1080p30 screen content in software: 8 Mbit/s.
    fn default() -> Self {
        Self {
            bitrate_bps: 8_000_000,
            max_fps: 30,
        }
    }
}

/// What the encoder produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedInfo {
    /// The frame decodes without earlier frames.
    pub keyframe: bool,
}

/// An H.264 encoder (Annex B output, no B-frames).
pub trait VideoEncoder: Send {
    /// Display name.
    fn name(&self) -> &str;

    /// Encodes `picture` into `out` (cleared first). `keyframe` forces an
    /// IDR frame. A size change starts a new stream with a keyframe.
    ///
    /// `out` stays empty when the rate controller skipped the frame: send
    /// nothing, and encode the latest picture again soon so the Viewer
    /// does not keep a stale image (a pending keyframe request stays
    /// pending until a keyframe is produced).
    ///
    /// # Errors
    /// [`MediaError::Codec`].
    fn encode(
        &mut self,
        picture: &I420,
        keyframe: bool,
        out: &mut Vec<u8>,
    ) -> Result<EncodedInfo, MediaError>;
}

/// An H.264 decoder.
pub trait VideoDecoder: Send {
    /// Display name.
    fn name(&self) -> &str;

    /// Decodes one access unit. Returns `true` and fills `out` when a
    /// picture is ready.
    ///
    /// # Errors
    /// [`MediaError::Codec`] for a corrupt or undecodable stream: the
    /// caller should request a keyframe.
    fn decode(&mut self, bitstream: &[u8], out: &mut I420) -> Result<bool, MediaError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A moving gradient with sharp text-like edges, as BGRA.
    #[allow(clippy::cast_possible_truncation)] // values are at most 255
    fn test_image(width: usize, height: usize, shift: usize) -> Vec<u8> {
        let mut image = Vec::with_capacity(width * height * 4);
        for y in 0..height {
            for x in 0..width {
                let edge = if (x / 8 + y / 8) % 2 == 0 { 255 } else { 0 };
                let r = ((x + shift) * 255 / width) as u8;
                let g = (y * 255 / height) as u8;
                image.extend_from_slice(&[edge, g, r, 255]);
            }
        }
        image
    }

    fn mean_abs_diff(a: &[u8], b: &[u8]) -> f64 {
        let total: u64 = a
            .iter()
            .zip(b)
            .map(|(x, y)| u64::from(x.abs_diff(*y)))
            .sum();
        total as f64 / a.len() as f64
    }

    #[test]
    fn encode_decode_round_trip() {
        let (width, height) = (320, 240);
        let mut encoder = OpenH264Encoder::new(&EncoderSettings::default()).unwrap();
        let mut decoder = OpenH264Decoder::new().unwrap();
        let mut picture = I420::default();
        let mut decoded = I420::default();
        let mut bitstream = Vec::new();

        for frame in 0..5 {
            let image = test_image(width, height, frame * 4);
            bgra_to_i420(&image, width * 4, width, height, &mut picture).unwrap();
            let info = encoder.encode(&picture, false, &mut bitstream).unwrap();
            assert_eq!(info.keyframe, frame == 0, "frame {frame}");
            assert!(!bitstream.is_empty());
            assert!(decoder.decode(&bitstream, &mut decoded).unwrap());
            assert_eq!((decoded.width(), decoded.height()), (width, height));
            let diff = mean_abs_diff(picture.y(), decoded.y());
            assert!(
                diff < 6.0,
                "frame {frame}: luma differs by {diff:.2} on average"
            );
        }

        // A forced keyframe is an IDR frame.
        let info = encoder.encode(&picture, true, &mut bitstream).unwrap();
        assert!(info.keyframe);
        assert!(decoder.decode(&bitstream, &mut decoded).unwrap());
    }

    #[test]
    fn size_change_restarts_with_a_keyframe() {
        let mut encoder = OpenH264Encoder::new(&EncoderSettings::default()).unwrap();
        let mut decoder = OpenH264Decoder::new().unwrap();
        let mut picture = I420::default();
        let mut decoded = I420::default();
        let mut bitstream = Vec::new();
        for (width, height) in [(320, 240), (160, 120)] {
            let image = test_image(width, height, 0);
            bgra_to_i420(&image, width * 4, width, height, &mut picture).unwrap();
            let info = encoder.encode(&picture, false, &mut bitstream).unwrap();
            assert!(info.keyframe);
            assert!(decoder.decode(&bitstream, &mut decoded).unwrap());
            assert_eq!((decoded.width(), decoded.height()), (width, height));
        }
    }

    /// Per-stage cost at 1080p. Run in release:
    /// `cargo test -p rr-media --release -- --ignored --nocapture`.
    #[test]
    #[ignore = "benchmark"]
    fn bench_1080p() {
        use std::time::Instant;
        let (width, height) = (1920, 1080);
        let mut encoder = OpenH264Encoder::new(&EncoderSettings::default()).unwrap();
        let mut decoder = OpenH264Decoder::new().unwrap();
        let (mut picture, mut decoded, mut bitstream) =
            (I420::default(), I420::default(), Vec::new());
        let images: Vec<Vec<u8>> = (0..4).map(|i| test_image(width, height, i * 16)).collect();
        let (mut convert, mut encode, mut decode, mut bytes) = (0.0, 0.0, 0.0, 0);
        let frames = 60;
        for frame in 0..frames {
            let image = &images[frame % images.len()];
            let started = Instant::now();
            bgra_to_i420(image, width * 4, width, height, &mut picture).unwrap();
            convert += started.elapsed().as_secs_f64();
            let started = Instant::now();
            encoder
                .encode(&picture, frame == 0, &mut bitstream)
                .unwrap();
            encode += started.elapsed().as_secs_f64();
            bytes += bitstream.len();
            let started = Instant::now();
            if !bitstream.is_empty() {
                decoder.decode(&bitstream, &mut decoded).unwrap();
            }
            decode += started.elapsed().as_secs_f64();
        }
        let ms = |total: f64| total * 1000.0 / frames as f64;
        println!(
            "1080p per frame: convert {:.2} ms, encode {:.2} ms, decode {:.2} ms, {} KiB",
            ms(convert),
            ms(encode),
            ms(decode),
            bytes / frames / 1024
        );
    }

    #[test]
    fn garbage_does_not_decode_and_does_not_panic() {
        let mut decoder = OpenH264Decoder::new().unwrap();
        let mut out = I420::default();
        for garbage in [&[][..], &[0, 0, 0, 1, 0xFF, 0xFF], &[0xAB; 4096]] {
            let _ = decoder.decode(garbage, &mut out);
        }
    }
}
