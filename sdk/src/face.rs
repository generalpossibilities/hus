//! Face images: camera frames in the formats phones deliver, and the
//! 5-point alignment that turns a detected face into the 112×112 crop the
//! face model expects.
//!
//! Coordinates: the face detector works on the *upright* image (the camera
//! buffer rotated by `rotation` degrees clockwise). Landmarks and boxes are
//! given in upright pixels; [`Frame`] maps them back into the raw buffer.

use alloc::vec::Vec;

/// Pixel layout of a camera buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 4 bytes per pixel, R G B A.
    Rgba,
    /// 4 bytes per pixel, B G R A (iOS camera).
    Bgra,
    /// Y plane (`stride` bytes per row, `height` rows), then interleaved
    /// V/U at half resolution with the same stride (Android camera).
    Nv21,
}

impl PixelFormat {
    pub fn from_id(id: u32) -> Option<Self> {
        match id {
            0 => Some(PixelFormat::Rgba),
            1 => Some(PixelFormat::Bgra),
            2 => Some(PixelFormat::Nv21),
            _ => None,
        }
    }
}

/// One camera buffer, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub format: PixelFormat,
    pub width: usize,
    pub height: usize,
    /// Bytes per row (of the Y plane for NV21).
    pub stride: usize,
    /// Clockwise rotation (0, 90, 180, 270) that makes the buffer upright.
    pub rotation: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    BadDimensions,
    BadRotation,
    TooSmall,
}

impl<'a> Frame<'a> {
    pub fn new(
        format: PixelFormat,
        width: usize,
        height: usize,
        stride: usize,
        rotation: u16,
        data: &'a [u8],
    ) -> Result<Self, FrameError> {
        if width < 16 || height < 16 || width > 8192 || height > 8192 {
            return Err(FrameError::BadDimensions);
        }
        if !matches!(rotation, 0 | 90 | 180 | 270) {
            return Err(FrameError::BadRotation);
        }
        let needed = match format {
            PixelFormat::Rgba | PixelFormat::Bgra => {
                if stride < width * 4 {
                    return Err(FrameError::BadDimensions);
                }
                stride * (height - 1) + width * 4
            }
            PixelFormat::Nv21 => {
                if stride < width || width % 2 != 0 || height % 2 != 0 {
                    return Err(FrameError::BadDimensions);
                }
                stride * height + stride * (height / 2 - 1) + width
            }
        };
        if data.len() < needed {
            return Err(FrameError::TooSmall);
        }
        Ok(Frame { format, width, height, stride, rotation, data })
    }

    /// Size of the upright image.
    pub fn upright_size(&self) -> (usize, usize) {
        if self.rotation % 180 == 0 {
            (self.width, self.height)
        } else {
            (self.height, self.width)
        }
    }

    /// Upright pixel position → raw buffer position.
    fn to_raw(&self, u: f32, v: f32) -> (f32, f32) {
        let (w, h) = (self.width as f32, self.height as f32);
        match self.rotation {
            90 => (v, h - 1.0 - u),
            180 => (w - 1.0 - u, h - 1.0 - v),
            270 => (w - 1.0 - v, u),
            _ => (u, v),
        }
    }

    /// RGB of one raw pixel (clamped to the buffer).
    fn rgb(&self, x: usize, y: usize) -> [f32; 3] {
        let x = x.min(self.width - 1);
        let y = y.min(self.height - 1);
        match self.format {
            PixelFormat::Rgba => {
                let i = y * self.stride + x * 4;
                [self.data[i] as f32, self.data[i + 1] as f32, self.data[i + 2] as f32]
            }
            PixelFormat::Bgra => {
                let i = y * self.stride + x * 4;
                [self.data[i + 2] as f32, self.data[i + 1] as f32, self.data[i] as f32]
            }
            PixelFormat::Nv21 => {
                let yy = self.data[y * self.stride + x] as f32;
                let uv = self.stride * self.height + (y / 2) * self.stride + (x & !1);
                let v = self.data[uv] as f32 - 128.0;
                let u = self.data[uv + 1] as f32 - 128.0;
                // BT.601 full range, as camera NV21 buffers are.
                [
                    clamp255(yy + 1.402 * v),
                    clamp255(yy - 0.344_136 * u - 0.714_136 * v),
                    clamp255(yy + 1.772 * u),
                ]
            }
        }
    }

    /// Bilinear RGB at an upright position.
    fn sample(&self, u: f32, v: f32) -> [f32; 3] {
        let (x, y) = self.to_raw(u, v);
        let x = x.clamp(0.0, (self.width - 1) as f32);
        let y = y.clamp(0.0, (self.height - 1) as f32);
        let (x0, y0) = (x as usize, y as usize);
        let (fx, fy) = (x - x0 as f32, y - y0 as f32);
        let p00 = self.rgb(x0, y0);
        let p10 = self.rgb(x0 + 1, y0);
        let p01 = self.rgb(x0, y0 + 1);
        let p11 = self.rgb(x0 + 1, y0 + 1);
        let mut out = [0.0; 3];
        for c in 0..3 {
            let top = p00[c] + (p10[c] - p00[c]) * fx;
            let bottom = p01[c] + (p11[c] - p01[c]) * fx;
            out[c] = top + (bottom - top) * fy;
        }
        out
    }
}

fn clamp255(x: f32) -> f32 {
    x.clamp(0.0, 255.0)
}

/// Side of the aligned face crop.
pub const ALIGNED_SIZE: usize = 112;

/// Where the five landmarks sit in a 112×112 ArcFace crop: left eye, right
/// eye, nose tip, left mouth corner, right mouth corner (the subject's
/// left/right as seen in the image: "left" is the one with smaller x).
pub const ARCFACE_TEMPLATE: [[f32; 2]; 5] = [
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041],
];

/// A similarity transform `q = M p + t`, `M = [[a, -b], [b, a]]`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Similarity {
    pub a: f32,
    pub b: f32,
    pub tx: f32,
    pub ty: f32,
}

impl Similarity {
    /// Least-squares similarity (rotation, uniform scale, translation; no
    /// reflection) taking `src` onto `dst` (Umeyama).
    pub fn estimate(src: &[[f32; 2]; 5], dst: &[[f32; 2]; 5]) -> Option<Self> {
        let n = src.len() as f32;
        let (mut sx, mut sy, mut dx, mut dy) = (0.0, 0.0, 0.0, 0.0);
        for i in 0..5 {
            sx += src[i][0];
            sy += src[i][1];
            dx += dst[i][0];
            dy += dst[i][1];
        }
        let (sx, sy, dx, dy) = (sx / n, sy / n, dx / n, dy / n);
        let (mut num_a, mut num_b, mut var) = (0.0, 0.0, 0.0);
        for i in 0..5 {
            let (px, py) = (src[i][0] - sx, src[i][1] - sy);
            let (qx, qy) = (dst[i][0] - dx, dst[i][1] - dy);
            num_a += px * qx + py * qy;
            num_b += px * qy - py * qx;
            var += px * px + py * py;
        }
        if !(var > 1e-3) {
            return None;
        }
        let a = num_a / var;
        let b = num_b / var;
        Some(Similarity {
            a,
            b,
            tx: dx - (a * sx - b * sy),
            ty: dy - (b * sx + a * sy),
        })
    }

    pub fn apply(&self, p: [f32; 2]) -> [f32; 2] {
        [
            self.a * p[0] - self.b * p[1] + self.tx,
            self.b * p[0] + self.a * p[1] + self.ty,
        ]
    }

    pub fn inverse(&self) -> Option<Self> {
        let d = self.a * self.a + self.b * self.b;
        if !(d > 1e-12) {
            return None;
        }
        let (a, b) = (self.a / d, -self.b / d);
        Some(Similarity {
            a,
            b,
            tx: -(a * self.tx - b * self.ty),
            ty: -(b * self.tx + a * self.ty),
        })
    }

    pub fn scale(&self) -> f32 {
        libm::sqrtf(self.a * self.a + self.b * self.b)
    }
}

/// Warp the face whose upright landmarks are `landmarks` into a 112×112
/// RGBA crop aligned to [`ARCFACE_TEMPLATE`]. `None` if the landmarks are
/// degenerate.
pub fn align_face(frame: &Frame, landmarks: &[[f32; 2]; 5]) -> Option<Vec<u8>> {
    if landmarks.iter().any(|p| !p[0].is_finite() || !p[1].is_finite()) {
        return None;
    }
    let to_crop = Similarity::estimate(landmarks, &ARCFACE_TEMPLATE)?;
    let to_frame = to_crop.inverse()?;
    let mut out = Vec::with_capacity(ALIGNED_SIZE * ALIGNED_SIZE * 4);
    for y in 0..ALIGNED_SIZE {
        for x in 0..ALIGNED_SIZE {
            let p = to_frame.apply([x as f32, y as f32]);
            let rgb = frame.sample(p[0], p[1]);
            out.push(libm::roundf(rgb[0]) as u8);
            out.push(libm::roundf(rgb[1]) as u8);
            out.push(libm::roundf(rgb[2]) as u8);
            out.push(255);
        }
    }
    Some(out)
}

/// Mean luma of an RGBA crop, 0–255.
pub fn mean_luma(rgba: &[u8]) -> f32 {
    let px = rgba.len() / 4;
    if px == 0 {
        return 0.0;
    }
    let mut sum = 0.0f32;
    for p in rgba.chunks_exact(4) {
        sum += 0.299 * p[0] as f32 + 0.587 * p[1] as f32 + 0.114 * p[2] as f32;
    }
    sum / px as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgba_gradient(w: usize, h: usize) -> Vec<u8> {
        let mut d = Vec::with_capacity(w * h * 4);
        for y in 0..h {
            for x in 0..w {
                d.extend_from_slice(&[(x % 256) as u8, (y % 256) as u8, 7, 255]);
            }
        }
        d
    }

    #[test]
    fn identity_landmarks_copy_the_template_area() {
        let (w, h) = (112, 112);
        let data = rgba_gradient(w, h);
        let f = Frame::new(PixelFormat::Rgba, w, h, w * 4, 0, &data).unwrap();
        let crop = align_face(&f, &ARCFACE_TEMPLATE).unwrap();
        assert_eq!(crop.len(), 112 * 112 * 4);
        for (x, y) in [(0usize, 0usize), (50, 60), (111, 111)] {
            let i = (y * 112 + x) * 4;
            assert_eq!(crop[i], x as u8);
            assert_eq!(crop[i + 1], y as u8);
            assert_eq!(crop[i + 2], 7);
        }
    }

    #[test]
    fn similarity_recovers_a_known_transform() {
        let t = Similarity { a: 0.8, b: 0.3, tx: 12.0, ty: -4.0 };
        let mut src = [[0.0f32; 2]; 5];
        let inv = t.inverse().unwrap();
        for i in 0..5 {
            src[i] = inv.apply(ARCFACE_TEMPLATE[i]);
        }
        let e = Similarity::estimate(&src, &ARCFACE_TEMPLATE).unwrap();
        assert!((e.a - t.a).abs() < 1e-4 && (e.b - t.b).abs() < 1e-4);
        assert!((e.tx - t.tx).abs() < 1e-2 && (e.ty - t.ty).abs() < 1e-2);
    }

    #[test]
    fn degenerate_landmarks_are_refused() {
        let data = rgba_gradient(64, 64);
        let f = Frame::new(PixelFormat::Rgba, 64, 64, 256, 0, &data).unwrap();
        assert!(align_face(&f, &[[10.0, 10.0]; 5]).is_none());
        let mut nan = ARCFACE_TEMPLATE;
        nan[2][0] = f32::NAN;
        assert!(align_face(&f, &nan).is_none());
    }

    // A raw buffer rotated 90° and read with rotation=90 gives the same
    // crop as the upright buffer read with rotation=0.
    #[test]
    fn rotation_maps_upright_points_into_the_buffer() {
        let (uw, uh) = (40usize, 30usize);
        let upright = rgba_gradient(uw, uh);
        for rot in [90u16, 180, 270] {
            // Build the raw buffer such that rotating it `rot` cw is upright.
            let (rw, rh) = if rot == 180 { (uw, uh) } else { (uh, uw) };
            let mut raw = vec![0u8; rw * rh * 4];
            let probe = Frame::new(PixelFormat::Rgba, rw, rh, rw * 4, rot, &raw).unwrap();
            let mut map = Vec::new();
            for v in 0..uh {
                for u in 0..uw {
                    let (x, y) = probe.to_raw(u as f32, v as f32);
                    map.push(((u, v), (x as usize, y as usize)));
                }
            }
            for ((u, v), (x, y)) in map {
                let s = (v * uw + u) * 4;
                let d = (y * rw + x) * 4;
                raw[d..d + 4].copy_from_slice(&upright[s..s + 4]);
            }
            let f = Frame::new(PixelFormat::Rgba, rw, rh, rw * 4, rot, &raw).unwrap();
            assert_eq!(f.upright_size(), (uw, uh));
            for (u, v) in [(0usize, 0usize), (39, 0), (0, 29), (17, 11)] {
                let got = f.sample(u as f32, v as f32);
                assert_eq!(got[0] as usize, u, "rot {rot} at ({u},{v})");
                assert_eq!(got[1] as usize, v, "rot {rot} at ({u},{v})");
            }
        }
    }

    #[test]
    fn nv21_and_bgra_decode() {
        let (w, h) = (16usize, 16usize);
        // Mid-grey NV21 (Y=128, U=V=128) → RGB 128.
        let mut nv = vec![128u8; w * h + w * h / 2];
        nv[0] = 200;
        let f = Frame::new(PixelFormat::Nv21, w, h, w, 0, &nv).unwrap();
        assert_eq!(f.rgb(5, 5), [128.0, 128.0, 128.0]);
        assert_eq!(f.rgb(0, 0), [200.0, 200.0, 200.0]);
        // Pure red in NV21: V high.
        let mut red = vec![76u8; w * h];
        for _ in 0..(w * h / 4) {
            red.extend_from_slice(&[255, 85]);
        }
        let f = Frame::new(PixelFormat::Nv21, w, h, w, 0, &red).unwrap();
        let p = f.rgb(3, 3);
        assert!(p[0] > 240.0 && p[1] < 20.0 && p[2] < 20.0, "{p:?}");

        let bgra = [10u8, 20, 30, 255].repeat(w * h);
        let f = Frame::new(PixelFormat::Bgra, w, h, w * 4, 0, &bgra).unwrap();
        assert_eq!(f.rgb(1, 1), [30.0, 20.0, 10.0]);
    }

    #[test]
    fn frames_too_small_for_their_size_are_refused() {
        let d = vec![0u8; 100];
        assert_eq!(
            Frame::new(PixelFormat::Rgba, 32, 32, 128, 0, &d).unwrap_err(),
            FrameError::TooSmall
        );
        assert_eq!(
            Frame::new(PixelFormat::Rgba, 32, 32, 128, 45, &d).unwrap_err(),
            FrameError::BadRotation
        );
    }
}
