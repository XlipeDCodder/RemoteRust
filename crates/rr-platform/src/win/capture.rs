//! DXGI Desktop Duplication (blueprint v2 §3, §8.3), M2 CPU path:
//! acquire the desktop texture, copy it to a CPU-readable staging texture
//! and hand the mapped BGRA pixels to the caller.
//!
//! DXGI only returns a frame when the screen changed, so a static screen
//! costs a blocking wait and nothing else. The mouse pointer is not part
//! of the image; it travels separately (M3).
#![allow(unsafe_code)] // FFI module: every block below is justified with `SAFETY:`.

use std::time::{Duration, Instant};

use windows::Win32::Foundation::{E_ACCESSDENIED, HMODULE};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_NOT_FOUND, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_FRAME_INFO, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput, IDXGIOutput1,
    IDXGIOutputDuplication, IDXGIResource,
};
use windows::core::Interface;

use crate::capture::{CaptureError, Frame, MAX_MONITORS, Monitor, ScreenCapturer};
use crate::win::os_error;

/// An attached output and the adapter that drives it.
struct Output {
    monitor: Monitor,
    adapter: IDXGIAdapter1,
    output: IDXGIOutput,
}

/// Enumerates attached outputs, adapter by adapter, in a stable order.
fn outputs() -> Result<Vec<Output>, CaptureError> {
    // SAFETY: plain factory creation; the returned interface is owned.
    let factory: IDXGIFactory1 =
        unsafe { CreateDXGIFactory1() }.map_err(|err| os_error("CreateDXGIFactory1", &err))?;
    let mut found = Vec::new();
    for adapter_index in 0u32.. {
        // SAFETY: enumeration call; DXGI_ERROR_NOT_FOUND marks the end.
        let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(adapter) => adapter,
            Err(err) if err.code() == DXGI_ERROR_NOT_FOUND => break,
            Err(err) => return Err(os_error("EnumAdapters1", &err)),
        };
        for output_index in 0u32.. {
            // SAFETY: as above, per output of this adapter.
            let output = match unsafe { adapter.EnumOutputs(output_index) } {
                Ok(output) => output,
                Err(err) if err.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(err) => return Err(os_error("EnumOutputs", &err)),
            };
            // SAFETY: reads the output description into an owned struct.
            let desc = unsafe { output.GetDesc() }.map_err(|err| os_error("GetDesc", &err))?;
            if !desc.AttachedToDesktop.as_bool() || found.len() >= MAX_MONITORS {
                continue;
            }
            let rect = desc.DesktopCoordinates;
            let name_len = desc
                .DeviceName
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(desc.DeviceName.len());
            let name = String::from_utf16_lossy(desc.DeviceName.get(..name_len).unwrap_or(&[]));
            let id = u8::try_from(found.len()).unwrap_or(u8::MAX);
            found.push(Output {
                monitor: Monitor {
                    id,
                    name: name.trim_start_matches(r"\\.\").to_owned(),
                    width: rect.right.abs_diff(rect.left),
                    height: rect.bottom.abs_diff(rect.top),
                    left: rect.left,
                    top: rect.top,
                    // The primary monitor's top-left corner is the origin
                    // of the virtual desktop.
                    primary: rect.left == 0 && rect.top == 0,
                },
                adapter: adapter.clone(),
                output,
            });
        }
    }
    Ok(found)
}

pub(crate) fn monitors() -> Result<Vec<Monitor>, CaptureError> {
    Ok(outputs()?
        .into_iter()
        .map(|output| output.monitor)
        .collect())
}

/// Desktop Duplication of one output.
pub(crate) struct DxgiCapturer {
    monitor: Monitor,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    output: IDXGIOutput1,
    /// `None` after the duplication was lost; recreated on the next capture.
    duplication: Option<IDXGIOutputDuplication>,
    /// CPU-readable copy target, recreated when the size changes.
    staging: Option<(ID3D11Texture2D, u32, u32)>,
}

impl DxgiCapturer {
    pub(crate) fn open(id: u8) -> Result<Self, CaptureError> {
        let Output {
            monitor,
            adapter,
            output,
        } = outputs()?
            .into_iter()
            .find(|output| output.monitor.id == id)
            .ok_or(CaptureError::NoSuchMonitor(id))?;

        let mut device = None;
        let mut context = None;
        // SAFETY: creates a device on the adapter that drives the output
        // (required by DuplicateOutput); the out-parameters are valid
        // `Option`s owned by this frame.
        unsafe {
            D3D11CreateDevice(
                &adapter,
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
        }
        .map_err(|err| os_error("D3D11CreateDevice", &err))?;
        let missing = |context| CaptureError::Os {
            context,
            code: 0,
            message: "no interface returned".to_owned(),
        };
        let device = device.ok_or_else(|| missing("D3D11CreateDevice"))?;
        let context = context.ok_or_else(|| missing("D3D11CreateDevice"))?;
        let output: IDXGIOutput1 = output
            .cast()
            .map_err(|err| os_error("IDXGIOutput1", &err))?;

        let mut capturer = Self {
            monitor,
            device,
            context,
            output,
            duplication: None,
            staging: None,
        };
        capturer.duplicate()?;
        Ok(capturer)
    }

    fn duplicate(&mut self) -> Result<IDXGIOutputDuplication, CaptureError> {
        // SAFETY: duplicates this output for this device; the result is an
        // owned interface.
        let duplication = unsafe { self.output.DuplicateOutput(&self.device) }.map_err(|err| {
            // Access denied: the secure desktop (UAC, lock screen) is
            // showing, which only SYSTEM may capture. It goes away again.
            if err.code() == DXGI_ERROR_ACCESS_LOST || err.code() == E_ACCESSDENIED {
                CaptureError::AccessLost
            } else {
                os_error("DuplicateOutput", &err)
            }
        })?;
        // The output may have moved or changed resolution (that is what
        // usually loses the duplication): input mapping follows `monitor`.
        // SAFETY: reads the output description into an owned struct.
        if let Ok(desc) = unsafe { self.output.GetDesc() } {
            let rect = desc.DesktopCoordinates;
            self.monitor.left = rect.left;
            self.monitor.top = rect.top;
            self.monitor.width = rect.right.abs_diff(rect.left);
            self.monitor.height = rect.bottom.abs_diff(rect.top);
        }
        self.duplication = Some(duplication.clone());
        Ok(duplication)
    }

    fn staging(&mut self, width: u32, height: u32) -> Result<ID3D11Texture2D, CaptureError> {
        if let Some((texture, w, h)) = &self.staging
            && (*w, *h) == (width, height)
        {
            return Ok(texture.clone());
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0.cast_unsigned(),
            MiscFlags: 0,
        };
        let mut texture = None;
        // SAFETY: `desc` is a valid staging description and `texture` a
        // valid out-parameter; no initial data.
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut texture)) }
            .map_err(|err| os_error("CreateTexture2D", &err))?;
        let texture = texture.ok_or(CaptureError::Os {
            context: "CreateTexture2D",
            code: 0,
            message: "no texture returned".to_owned(),
        })?;
        self.staging = Some((texture.clone(), width, height));
        Ok(texture)
    }
}

/// Releases an acquired frame when dropped, on every path.
struct Acquired<'a>(&'a IDXGIOutputDuplication);

impl Drop for Acquired<'_> {
    fn drop(&mut self) {
        // SAFETY: called exactly once per successful AcquireNextFrame.
        let _ = unsafe { self.0.ReleaseFrame() };
    }
}

/// Unmaps the staging texture when dropped.
struct Mapped<'a> {
    context: &'a ID3D11DeviceContext,
    texture: &'a ID3D11Texture2D,
}

impl Drop for Mapped<'_> {
    fn drop(&mut self) {
        // SAFETY: the texture was mapped (subresource 0) by this context,
        // and no slice into the mapping outlives this guard.
        unsafe { self.context.Unmap(self.texture, 0) };
    }
}

impl ScreenCapturer for DxgiCapturer {
    fn monitor(&self) -> &Monitor {
        &self.monitor
    }

    fn capture(
        &mut self,
        timeout: Duration,
        on_frame: &mut dyn FnMut(Frame<'_>),
    ) -> Result<bool, CaptureError> {
        let duplication = match &self.duplication {
            Some(duplication) => duplication.clone(),
            None => self.duplicate()?,
        };
        let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        // SAFETY: valid out-parameters owned by this frame; a successful
        // acquire is paired with ReleaseFrame by `Acquired`.
        let acquired =
            unsafe { duplication.AcquireNextFrame(timeout_ms, &mut info, &mut resource) };
        match acquired {
            Ok(()) => {}
            Err(err) if err.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(false),
            Err(err) if err.code() == DXGI_ERROR_ACCESS_LOST => {
                self.duplication = None;
                return Err(CaptureError::AccessLost);
            }
            Err(err) => return Err(os_error("AcquireNextFrame", &err)),
        }
        let acquired_at = Instant::now();
        let frame = Acquired(&duplication);
        // No new image: only the pointer moved. This includes the first
        // frame of a new duplication, whose texture is not populated yet
        // (black on AMD); the real starting image follows with the next
        // desktop present, which DWM issues within ~100 ms of duplicating
        // and on any screen change.
        if info.LastPresentTime == 0 {
            return Ok(false);
        }
        let texture: ID3D11Texture2D = resource
            .ok_or(CaptureError::Os {
                context: "AcquireNextFrame",
                code: 0,
                message: "no desktop resource returned".to_owned(),
            })?
            .cast()
            .map_err(|err| os_error("ID3D11Texture2D", &err))?;
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: writes the description of a live texture into `desc`.
        unsafe { texture.GetDesc(&mut desc) };
        let staging = self.staging(desc.Width, desc.Height)?;
        // SAFETY: both textures belong to this device and have the same
        // size and format (the staging texture was created from `desc`).
        unsafe { self.context.CopyResource(&staging, &texture) };
        // Give the image back to DXGI as early as possible.
        drop(frame);

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: maps subresource 0 of a CPU-readable staging texture;
        // `Mapped` unmaps it on every path.
        unsafe {
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
        }
        .map_err(|err| os_error("Map", &err))?;
        let _unmap = Mapped {
            context: &self.context,
            texture: &staging,
        };
        let stride = usize::try_from(mapped.RowPitch).unwrap_or(0);
        let height = usize::try_from(desc.Height).unwrap_or(0);
        let width_bytes = usize::try_from(desc.Width).unwrap_or(0).saturating_mul(4);
        if mapped.pData.is_null() || stride < width_bytes {
            return Err(CaptureError::Os {
                context: "Map",
                code: 0,
                message: "unexpected mapping layout".to_owned(),
            });
        }
        let len = stride.saturating_mul(height);
        // SAFETY: a successful Map of a `Height`-row texture yields at least
        // `RowPitch * Height` readable bytes at `pData`, valid until Unmap,
        // which `_unmap` performs only after `on_frame` returns.
        let bgra = unsafe { std::slice::from_raw_parts(mapped.pData.cast::<u8>(), len) };
        on_frame(Frame {
            width: desc.Width,
            height: desc.Height,
            stride,
            bgra,
            accumulated: info.AccumulatedFrames.max(1),
            acquired: acquired_at,
        });
        Ok(true)
    }
}
