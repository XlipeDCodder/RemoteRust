//! GPU presentation (blueprint v2 §8.6).
//!
//! The decoded picture is uploaded as three R8 textures (Y, U, V) and a
//! shader converts it to RGB while drawing it letterboxed into the window.
//! The egui overlay is drawn on top, in the same render pass.

use std::sync::Arc;

use anyhow::Context as _;
use rr_media::I420;
use winit::window::Window;

/// An overlay frame ready to draw.
pub struct OverlayFrame {
    pub primitives: Vec<egui::ClippedPrimitive>,
    pub textures: egui::TexturesDelta,
    pub pixels_per_point: f32,
}

pub struct Renderer {
    instance: wgpu::Instance,
    window: Arc<Window>,
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    /// Format the shaders write: the surface format without `Srgb`.
    view_format: wgpu::TextureFormat,
    pipeline: wgpu::RenderPipeline,
    layout: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
    planes: Option<Planes>,
    egui: egui_wgpu::Renderer,
    description: String,
    warned_too_large: bool,
}

/// GPU copies of the current picture.
struct Planes {
    width: u32,
    height: u32,
    textures: [wgpu::Texture; 3],
    bind_group: wgpu::BindGroup,
}

impl Renderer {
    pub async fn new(instance: wgpu::Instance, window: Arc<Window>) -> anyhow::Result<Self> {
        let surface = instance
            .create_surface(Arc::clone(&window))
            .context("cannot create a drawing surface for the window")?;
        let adapter = match native_adapter(&instance, &surface).await {
            Some(adapter) => adapter,
            None => instance
                .request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::LowPower,
                    compatible_surface: Some(&surface),
                    ..Default::default()
                })
                .await
                .context("no graphics adapter can draw to this window")?,
        };
        let info = adapter.get_info();
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("rr-viewer"),
                required_limits: adapter.limits(),
                ..Default::default()
            })
            .await
            .context("cannot open the graphics device")?;

        let caps = surface.get_capabilities(&adapter);
        let format = caps
            .formats
            .iter()
            .copied()
            .find(|format| !format.is_srgb())
            .or_else(|| caps.formats.first().copied())
            .context("the window surface supports no pixel format")?;
        let view_format = format.remove_srgb_suffix();
        // Mailbox shows the newest frame at the next refresh without tearing
        // and never blocks; FIFO (always available) may wait for vsync.
        let present_mode = if caps.present_modes.contains(&wgpu::PresentMode::Mailbox) {
            wgpu::PresentMode::Mailbox
        } else {
            wgpu::PresentMode::Fifo
        };
        let size = window.inner_size();
        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            color_space: wgpu::SurfaceColorSpace::Auto,
            width: size.width,
            height: size.height,
            present_mode,
            desired_maximum_frame_latency: 1,
            alpha_mode: caps
                .alpha_modes
                .first()
                .copied()
                .unwrap_or(wgpu::CompositeAlphaMode::Auto),
            view_formats: if view_format == format {
                Vec::new()
            } else {
                vec![view_format]
            },
        };

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("yuv"),
            source: wgpu::ShaderSource::Wgsl(include_str!("yuv.wgsl").into()),
        });
        let plane = |binding| wgpu::BindGroupLayoutEntry {
            binding,
            visibility: wgpu::ShaderStages::FRAGMENT,
            ty: wgpu::BindingType::Texture {
                sample_type: wgpu::TextureSampleType::Float { filterable: true },
                view_dimension: wgpu::TextureViewDimension::D2,
                multisampled: false,
            },
            count: None,
        };
        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("yuv"),
            entries: &[
                plane(0),
                plane(1),
                plane(2),
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("yuv"),
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("yuv"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs_main"),
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                buffers: &[],
            },
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fs_main"),
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format: view_format,
                    blend: None,
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            multiview_mask: None,
            cache: None,
        });
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("yuv"),
            address_mode_u: wgpu::AddressMode::ClampToEdge,
            address_mode_v: wgpu::AddressMode::ClampToEdge,
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });
        let egui =
            egui_wgpu::Renderer::new(&device, view_format, egui_wgpu::RendererOptions::default());

        let renderer = Self {
            instance,
            window,
            surface,
            device,
            queue,
            description: format!("{} ({:?}, {present_mode:?})", info.name, info.backend),
            config,
            view_format,
            pipeline,
            layout,
            sampler,
            planes: None,
            egui,
            warned_too_large: false,
        };
        renderer.configure();
        Ok(renderer)
    }

    /// Adapter, backend and present mode, for the overlay.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Largest texture side the device accepts (for egui).
    pub fn max_texture_side(&self) -> usize {
        usize::try_from(self.device.limits().max_texture_dimension_2d).unwrap_or(usize::MAX)
    }

    fn configure(&self) {
        if self.config.width > 0 && self.config.height > 0 {
            self.surface.configure(&self.device, &self.config);
        }
    }

    /// Follows the window size (in physical pixels). A minimized window has
    /// size zero and is not drawn.
    pub fn resize(&mut self, width: u32, height: u32) {
        self.config.width = width;
        self.config.height = height;
        self.configure();
    }

    /// Copies `picture` to the GPU, recreating the textures when its size
    /// changes.
    pub fn upload(&mut self, picture: &I420) {
        let (Ok(width), Ok(height)) = (
            u32::try_from(picture.width()),
            u32::try_from(picture.height()),
        ) else {
            return;
        };
        let max = self.device.limits().max_texture_dimension_2d;
        if width == 0 || height == 0 || width > max || height > max {
            if !self.warned_too_large {
                tracing::warn!(width, height, max, "picture size not supported by the GPU");
                self.warned_too_large = true;
            }
            return;
        }
        if self
            .planes
            .as_ref()
            .is_none_or(|planes| (planes.width, planes.height) != (width, height))
        {
            self.planes = Some(self.create_planes(width, height));
        }
        let Some(planes) = &self.planes else {
            return;
        };
        let [y, u, v] = &planes.textures;
        let (chroma_width, chroma_height) = (width / 2, height / 2);
        for (texture, data, plane_width, plane_height) in [
            (y, picture.y(), width, height),
            (u, picture.u(), chroma_width, chroma_height),
            (v, picture.v(), chroma_width, chroma_height),
        ] {
            self.queue.write_texture(
                wgpu::TexelCopyTextureInfo {
                    texture,
                    mip_level: 0,
                    origin: wgpu::Origin3d::ZERO,
                    aspect: wgpu::TextureAspect::All,
                },
                data,
                wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(plane_width),
                    rows_per_image: Some(plane_height),
                },
                wgpu::Extent3d {
                    width: plane_width,
                    height: plane_height,
                    depth_or_array_layers: 1,
                },
            );
        }
    }

    fn create_planes(&self, width: u32, height: u32) -> Planes {
        let texture = |label, width, height| {
            self.device.create_texture(&wgpu::TextureDescriptor {
                label: Some(label),
                size: wgpu::Extent3d {
                    width,
                    height,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::R8Unorm,
                usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
                view_formats: &[],
            })
        };
        let textures = [
            texture("plane y", width, height),
            texture("plane u", width / 2, height / 2),
            texture("plane v", width / 2, height / 2),
        ];
        let views = textures
            .each_ref()
            .map(|texture| texture.create_view(&wgpu::TextureViewDescriptor::default()));
        let [y, u, v] = &views;
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("yuv"),
            layout: &self.layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: wgpu::BindingResource::TextureView(y),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: wgpu::BindingResource::TextureView(u),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: wgpu::BindingResource::TextureView(v),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: wgpu::BindingResource::Sampler(&self.sampler),
                },
            ],
        });
        Planes {
            width,
            height,
            textures,
            bind_group,
        }
    }

    /// Draws the current picture and, if given, the overlay. Returns
    /// `false` when nothing could be shown this time (minimized or
    /// occluded window, surface being recreated).
    pub fn render(&mut self, overlay: Option<OverlayFrame>) -> bool {
        // Texture updates must reach egui even when this frame is skipped,
        // or later frames would refer to textures it never received.
        if let Some(overlay) = &overlay {
            for (id, deltas) in &overlay.textures.set {
                for delta in deltas {
                    self.egui
                        .update_texture(&self.device, &self.queue, *id, delta);
                }
            }
        }
        let shown = self.draw(overlay.as_ref());
        if let Some(overlay) = &overlay {
            for id in &overlay.textures.free {
                self.egui.free_texture(id);
            }
        }
        shown
    }

    fn draw(&mut self, overlay: Option<&OverlayFrame>) -> bool {
        if self.config.width == 0 || self.config.height == 0 {
            return false;
        }
        let (frame, suboptimal) = match self.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(frame) => (frame, false),
            wgpu::CurrentSurfaceTexture::Suboptimal(frame) => (frame, true),
            wgpu::CurrentSurfaceTexture::Timeout
            | wgpu::CurrentSurfaceTexture::Occluded
            | wgpu::CurrentSurfaceTexture::Validation => return false,
            wgpu::CurrentSurfaceTexture::Outdated => {
                self.configure();
                return false;
            }
            wgpu::CurrentSurfaceTexture::Lost => {
                match self.instance.create_surface(Arc::clone(&self.window)) {
                    Ok(surface) => {
                        self.surface = surface;
                        self.configure();
                    }
                    Err(err) => tracing::warn!(error = %err, "cannot recreate the window surface"),
                }
                return false;
            }
        };
        let view = frame.texture.create_view(&wgpu::TextureViewDescriptor {
            format: Some(self.view_format),
            ..Default::default()
        });
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("frame"),
            });
        let screen = egui_wgpu::ScreenDescriptor {
            size_in_pixels: [self.config.width, self.config.height],
            pixels_per_point: overlay.map_or(1.0, |overlay| overlay.pixels_per_point),
        };
        let egui_commands = overlay.map_or_else(Vec::new, |overlay| {
            self.egui.update_buffers(
                &self.device,
                &self.queue,
                &mut encoder,
                &overlay.primitives,
                &screen,
            )
        });
        {
            let mut pass = encoder
                .begin_render_pass(&wgpu::RenderPassDescriptor {
                    label: Some("frame"),
                    color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                        view: &view,
                        depth_slice: None,
                        resolve_target: None,
                        ops: wgpu::Operations {
                            load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                            store: wgpu::StoreOp::Store,
                        },
                    })],
                    depth_stencil_attachment: None,
                    timestamp_writes: None,
                    occlusion_query_set: None,
                    multiview_mask: None,
                })
                .forget_lifetime();
            if let Some(planes) = &self.planes {
                let [x, y, width, height] = letterbox(
                    (self.config.width, self.config.height),
                    (planes.width, planes.height),
                );
                pass.set_viewport(x, y, width, height, 0.0, 1.0);
                pass.set_pipeline(&self.pipeline);
                pass.set_bind_group(0, &planes.bind_group, &[]);
                pass.draw(0..3, 0..1);
            }
            if let Some(overlay) = overlay {
                self.egui.render(&mut pass, &overlay.primitives, &screen);
            }
        }
        self.queue
            .submit(egui_commands.into_iter().chain([encoder.finish()]));
        self.window.pre_present_notify();
        self.queue.present(frame);
        if suboptimal {
            self.configure();
        }
        true
    }
}

/// An adapter of the platform's own graphics API that can draw to
/// `surface`: D3D12 on Windows (flip-model presentation, integrated with
/// the compositor), Metal on macOS, Vulkan elsewhere. `WGPU_BACKEND`
/// (e.g. `vulkan`, `gl`) overrides the choice, for diagnosis.
///
/// The work per frame is tiny, so an integrated GPU comes first: on laptops
/// with two GPUs it usually drives the display, which avoids a copy between
/// adapters. Software adapters come last.
async fn native_adapter(
    instance: &wgpu::Instance,
    surface: &wgpu::Surface<'_>,
) -> Option<wgpu::Adapter> {
    let native = if cfg!(windows) {
        wgpu::Backends::DX12
    } else if cfg!(target_os = "macos") {
        wgpu::Backends::METAL
    } else {
        wgpu::Backends::VULKAN
    };
    let backends = wgpu::Backends::from_env().unwrap_or(native);
    instance
        .enumerate_adapters(backends)
        .await
        .into_iter()
        .filter(|adapter| adapter.is_surface_supported(surface))
        .min_by_key(|adapter| match adapter.get_info().device_type {
            wgpu::DeviceType::IntegratedGpu => 0,
            wgpu::DeviceType::DiscreteGpu => 1,
            wgpu::DeviceType::VirtualGpu | wgpu::DeviceType::Other => 2,
            wgpu::DeviceType::Cpu => 3,
        })
}

/// The largest rectangle with the picture's aspect ratio that fits the
/// window, centered and aligned to whole pixels: `[x, y, width, height]`.
#[allow(clippy::cast_precision_loss)] // sizes are far below 2^24
fn letterbox(window: (u32, u32), picture: (u32, u32)) -> [f32; 4] {
    let (window_width, window_height) = (window.0 as f32, window.1 as f32);
    let (picture_width, picture_height) = (picture.0.max(1) as f32, picture.1.max(1) as f32);
    let scale = (window_width / picture_width).min(window_height / picture_height);
    let width = (picture_width * scale).round().min(window_width);
    let height = (picture_height * scale).round().min(window_height);
    let x = ((window_width - width) / 2.0).floor();
    let y = ((window_height - height) / 2.0).floor();
    [x, y, width, height]
}

#[cfg(test)]
mod tests {
    use super::letterbox;

    #[test]
    fn letterbox_keeps_the_aspect_ratio() {
        // Same size: fills the window.
        assert_eq!(
            letterbox((1920, 1080), (1920, 1080)),
            [0.0, 0.0, 1920.0, 1080.0]
        );
        // Wider window: bars left and right.
        assert_eq!(
            letterbox((2000, 1080), (1920, 1080)),
            [40.0, 0.0, 1920.0, 1080.0]
        );
        // Taller window: bars above and below, scaled down.
        assert_eq!(
            letterbox((960, 1000), (1920, 1080)),
            [0.0, 230.0, 960.0, 540.0]
        );
        // Larger window: scaled up.
        assert_eq!(
            letterbox((3840, 2160), (1920, 1080)),
            [0.0, 0.0, 3840.0, 2160.0]
        );
    }
}
