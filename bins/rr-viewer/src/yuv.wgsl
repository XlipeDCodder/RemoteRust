// Draws a decoded I420 picture (three R8 planes) into the current viewport,
// converting BT.709 limited range ("TV" range) to RGB (blueprint v2 §8.6).
//
// The output target is a non-sRGB format: decoded values are already gamma
// encoded, so they are written as they are.

struct VertexOut {
    @builtin(position) position: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

// One triangle that covers the whole viewport: no vertex buffer needed.
@vertex
fn vs_main(@builtin(vertex_index) index: u32) -> VertexOut {
    let x = f32((index << 1u) & 2u);
    let y = f32(index & 2u);
    var out: VertexOut;
    out.position = vec4<f32>(x * 2.0 - 1.0, 1.0 - y * 2.0, 0.0, 1.0);
    out.uv = vec2<f32>(x, y);
    return out;
}

@group(0) @binding(0) var plane_y: texture_2d<f32>;
@group(0) @binding(1) var plane_u: texture_2d<f32>;
@group(0) @binding(2) var plane_v: texture_2d<f32>;
@group(0) @binding(3) var bilinear: sampler;

@fragment
fn fs_main(in: VertexOut) -> @location(0) vec4<f32> {
    // 8-bit limited range: Y in [16, 235], Cb and Cr in [16, 240].
    let y = (textureSample(plane_y, bilinear, in.uv).r - 16.0 / 255.0) * (255.0 / 219.0);
    let cb = (textureSample(plane_u, bilinear, in.uv).r - 128.0 / 255.0) * (255.0 / 224.0);
    let cr = (textureSample(plane_v, bilinear, in.uv).r - 128.0 / 255.0) * (255.0 / 224.0);
    // BT.709: Kr = 0.2126, Kb = 0.0722.
    let rgb = vec3<f32>(
        y + 1.5748 * cr,
        y - 0.1873 * cb - 0.4681 * cr,
        y + 1.8556 * cb,
    );
    return vec4<f32>(clamp(rgb, vec3<f32>(0.0), vec3<f32>(1.0)), 1.0);
}
