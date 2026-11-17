//! H.264 through OpenH264 (BSD-2-Clause, built from source): the software
//! encoder used when no hardware encoder works, and the M2 decoder
//! (blueprint v2 §8.4, §8.5).

use std::time::Instant;

use openh264::decoder::{Decoder, DecoderConfig, Flush};
use openh264::encoder::{
    BitRate, Complexity, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod,
    RateControlMode, UsageType, VuiConfig,
};
use openh264::formats::{YUVSlices, YUVSource};
use openh264::{OpenH264API, Timestamp};

use crate::yuv::I420;
use crate::{EncodedInfo, EncoderSettings, MediaError, VideoDecoder, VideoEncoder};

/// Software H.264 encoder tuned for screen content and low latency:
/// single slice, no B-frames, no periodic IDR (keyframes on demand only).
///
/// The rate controller may skip a frame to hold the bitrate (OpenH264
/// cannot control the rate otherwise); `encode` then returns an empty
/// bitstream and the caller re-encodes the latest picture shortly after.
pub struct OpenH264Encoder {
    encoder: Encoder,
    /// Origin of the frame timestamps. The rate controller measures the
    /// bitrate against them, so they must follow real time.
    epoch: Instant,
}

impl OpenH264Encoder {
    /// Display name for logs and the Viewer overlay.
    pub const NAME: &'static str = "openh264 (software)";

    /// Creates an encoder.
    ///
    /// # Errors
    /// [`MediaError::Codec`] if OpenH264 refuses the configuration.
    pub fn new(settings: &EncoderSettings) -> Result<Self, MediaError> {
        let config = EncoderConfig::new()
            .usage_type(UsageType::ScreenContentRealTime)
            .rate_control_mode(RateControlMode::Bitrate)
            .bitrate(BitRate::from_bps(settings.bitrate_bps))
            .max_frame_rate(FrameRate::from_hz(f32::from(settings.max_fps)))
            .skip_frames(true)
            // Neither is supported for screen content; OpenH264 warns and
            // turns them off anyway.
            .adaptive_quantization(false)
            .background_detection(false)
            .complexity(Complexity::Low)
            .intra_frame_period(IntraFramePeriod::from_num_frames(0))
            .vui(VuiConfig::bt709());
        let encoder = Encoder::with_api_config(OpenH264API::from_source(), config)
            .map_err(|err| MediaError::Codec(err.to_string()))?;
        Ok(Self {
            encoder,
            epoch: Instant::now(),
        })
    }
}

impl VideoEncoder for OpenH264Encoder {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn encode(
        &mut self,
        picture: &I420,
        keyframe: bool,
        out: &mut Vec<u8>,
    ) -> Result<EncodedInfo, MediaError> {
        if keyframe {
            self.encoder.force_intra_frame();
        }
        let source = YUVSlices::new(
            (picture.y(), picture.u(), picture.v()),
            (picture.width(), picture.height()),
            (picture.width(), picture.width() / 2, picture.width() / 2),
        );
        // Milliseconds since creation: u64 lasts far longer than any
        // session, and stays below the i64 range `encode_at` requires.
        let millis = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX >> 1);
        let bitstream = self
            .encoder
            .encode_at(&source, Timestamp::from_millis(millis))
            .map_err(|err| MediaError::Codec(err.to_string()))?;
        out.clear();
        let frame_type = bitstream.frame_type();
        if frame_type != FrameType::Skip {
            bitstream.write_vec(out);
        }
        Ok(EncodedInfo {
            keyframe: matches!(frame_type, FrameType::IDR | FrameType::I) && !out.is_empty(),
        })
    }
}

/// Software H.264 decoder. The bitstream comes only from authenticated
/// Agents, yet it is still C code parsing remote input (blueprint v2 §7.7).
pub struct OpenH264Decoder {
    decoder: Decoder,
}

impl OpenH264Decoder {
    /// Display name for the Viewer overlay.
    pub const NAME: &'static str = "openh264 (software)";

    /// Creates a decoder that returns each picture as soon as it is
    /// decoded (no reordering: the stream has no B-frames).
    ///
    /// # Errors
    /// [`MediaError::Codec`] if OpenH264 cannot be initialized.
    pub fn new() -> Result<Self, MediaError> {
        let config = DecoderConfig::new().flush_after_decode(Flush::NoFlush);
        let decoder = Decoder::with_api_config(OpenH264API::from_source(), config)
            .map_err(|err| MediaError::Codec(err.to_string()))?;
        Ok(Self { decoder })
    }
}

impl VideoDecoder for OpenH264Decoder {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn decode(&mut self, bitstream: &[u8], out: &mut I420) -> Result<bool, MediaError> {
        let Some(picture) = self
            .decoder
            .decode(bitstream)
            .map_err(|err| MediaError::Codec(err.to_string()))?
        else {
            return Ok(false);
        };
        let (width, height) = picture.dimensions();
        let (y_stride, u_stride, v_stride) = picture.strides();
        out.copy_from_planes(
            width,
            height,
            [
                (picture.y(), y_stride),
                (picture.u(), u_stride),
                (picture.v(), v_stride),
            ],
        )?;
        Ok(true)
    }
}
