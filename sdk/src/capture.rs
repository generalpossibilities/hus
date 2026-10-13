//! Raw biometric capture from device sensors.
//!
//! HUS owns the entire capture pipeline — no app ever sees the raw data.
//! Each modality defines how to capture from the appropriate sensor.
//!
//! ## Platform support
//!
//! - **WASM (browser):** `wasm-bindgen` bindings to `getUserMedia`,
//!   `DeviceMotionEvent`, keyboard / touch events.
//! - **Native (desktop / mobile FFI):** platform-specific camera / mic / sensor APIs
//!   feed raw buffers into this module.

use crate::config::Modality;
use crate::error::CaptureError;
#[cfg(target_arch = "wasm32")]
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Metadata about a raw capture
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct CaptureMeta {
    pub modality: Modality,
    /// Width in pixels (image) or number of channels (audio).
    pub width: u32,
    /// Height in pixels (0 for audio / sensor).
    pub height: u32,
    /// Sample rate (audio / accelerometer) or 0.
    pub sample_rate: u32,
    /// Timestamp (ms since epoch, best-effort).
    pub timestamp_ms: u64,
    /// Duration of the capture in ms.
    pub duration_ms: u32,
}

/// Earliest plausible capture timestamp: 2000-01-01T00:00:00Z in epoch ms.
pub const MIN_TIMESTAMP_MS: u64 = 946_684_800_000;
/// Maximum allowed device-clock drift into the future.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

// ---------------------------------------------------------------------------
// Raw sensor data — the app never sees this
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct RawCapture {
    pub meta: CaptureMeta,
    /// Raw bytes:
    ///   - Face / Iris: RGBA pixels (width × height × 4)
    ///   - Voice: PCM i16 interleaved
    ///   - Fingerprint: vendor-specific blob
    ///   - Keystroke: serialized key-event frames
    ///   - TouchGesture: serialized touch-event frames
    ///   - Gait: serialized accelerometer frames (x, y, z) × count
    pub data: Vec<u8>,
}

impl RawCapture {
    /// Validate capture metadata and data consistency.
    /// Returns `Ok(())` if all bounds checks pass.
    ///
    /// Under the `std` feature the timestamp is checked against the wall
    /// clock (allowing `MAX_CLOCK_SKEW_MS` of device-clock drift). Without
    /// `std` only the plausibility bounds are enforced.
    pub fn validate(&self) -> Result<(), CaptureError> {
        #[cfg(feature = "std")]
        {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0);
            self.validate_at(now_ms)
        }
        #[cfg(not(feature = "std"))]
        {
            self.validate_inner(None)
        }
    }

    /// Validate against an explicit wall-clock value (`now_ms`, epoch
    /// milliseconds). Rejects timestamps earlier than `MIN_TIMESTAMP_MS`
    /// and timestamps more than `MAX_CLOCK_SKEW_MS` in the future.
    pub fn validate_at(&self, now_ms: u64) -> Result<(), CaptureError> {
        self.validate_inner(Some(now_ms))
    }

    fn validate_inner(&self, now_ms: Option<u64>) -> Result<(), CaptureError> {
        if self.data.is_empty() {
            return Err(CaptureError::InsufficientData);
        }
        if self.meta.timestamp_ms == 0 {
            return Err(CaptureError::InvalidMetadata("timestamp_ms is 0"));
        }
        if self.meta.timestamp_ms < MIN_TIMESTAMP_MS {
            return Err(CaptureError::InvalidMetadata(
                "timestamp_ms before 2000-01-01 (implausible)",
            ));
        }
        if let Some(now) = now_ms {
            if self.meta.timestamp_ms > now.saturating_add(MAX_CLOCK_SKEW_MS) {
                return Err(CaptureError::InvalidMetadata(
                    "timestamp_ms is in the future",
                ));
            }
        }
        match self.meta.modality {
            Modality::Face | Modality::Iris => {
                if self.meta.width == 0 || self.meta.height == 0 {
                    return Err(CaptureError::InvalidMetadata("image width/height is 0"));
                }
                let expected = (self.meta.width as usize)
                    .checked_mul(self.meta.height as usize)
                    .and_then(|v| v.checked_mul(4))
                    .unwrap_or(usize::MAX);
                if self.data.len() < expected / 4 || self.data.len() > expected * 2 {
                    return Err(CaptureError::InvalidMetadata(
                        "image data size inconsistent with dimensions",
                    ));
                }
            }
            Modality::Voice => {
                if self.meta.sample_rate == 0 {
                    return Err(CaptureError::InvalidMetadata("sample_rate is 0 for audio"));
                }
                if self.meta.sample_rate > 192000 {
                    return Err(CaptureError::InvalidMetadata("sample_rate exceeds 192 kHz"));
                }
            }
            Modality::Fingerprint => {}
            _ => {}
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Key event for keystroke dynamics
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct KeyEvent {
    pub key_code: u32,
    pub press_time_ms: u64,
    pub release_time_ms: u64,
}

// ---------------------------------------------------------------------------
// Touch event for gesture dynamics
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct TouchEvent {
    pub x: f32,
    pub y: f32,
    pub pressure: f32,
    pub time_ms: u64,
}

// ---------------------------------------------------------------------------
// Accelerometer frame for gait analysis
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct AccelFrame {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub time_ms: u64,
}

// ---------------------------------------------------------------------------
// Capture trait — every modality implements this
// ---------------------------------------------------------------------------
pub trait Capture {
    fn modality(&self) -> Modality;
    /// Blocking capture from the device sensor.
    /// On WASM this may yield to the event loop.
    fn capture(&mut self) -> Result<RawCapture, CaptureError>;
}

// ---------------------------------------------------------------------------
// Platform-independent capture helpers (returned when no sensor available)
// ---------------------------------------------------------------------------
pub fn noop_capture(modality: Modality) -> RawCapture {
    RawCapture {
        meta: CaptureMeta {
            modality,
            width: 0,
            height: 0,
            sample_rate: 0,
            timestamp_ms: 0,
            duration_ms: 0,
        },
        data: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// WASM capture implementations
// ---------------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
pub mod wasm {
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    use js_sys::Uint8Array;
    use wasm_bindgen::{prelude::Closure, JsCast, JsValue};
    use wasm_bindgen_futures::{spawn_local, JsFuture};
    use web_sys::{
        window, BlobEvent, DeviceAcceleration, DeviceMotionEvent, Document, HtmlCanvasElement,
        KeyboardEvent, MediaRecorder, MediaStream, MediaStreamConstraints, MediaStreamTrack, Touch,
        TouchEvent, TouchList,
    };

    use super::*;
    use crate::error::CaptureError;

    // -----------------------------------------------------------------------
    // WebcamCapture — face and iris
    // -----------------------------------------------------------------------
    pub struct WebcamCapture {
        pub modality: Modality,
        pub width: u32,
        pub height: u32,
        stream: Option<MediaStream>,
        video: Option<web_sys::HtmlVideoElement>,
        canvas: Option<HtmlCanvasElement>,
    }

    impl WebcamCapture {
        pub fn face() -> Self {
            Self {
                modality: Modality::Face,
                width: 640,
                height: 480,
                stream: None,
                video: None,
                canvas: None,
            }
        }
        pub fn iris() -> Self {
            Self {
                modality: Modality::Iris,
                width: 1280,
                height: 720,
                stream: None,
                video: None,
                canvas: None,
            }
        }

        pub async fn start_stream(&mut self) -> Result<(), CaptureError> {
            let doc = document().ok_or(CaptureError::DeviceNotAvailable("no document"))?;
            let win = window().ok_or(CaptureError::DeviceNotAvailable("no window"))?;
            let nav = win.navigator();
            let media = nav
                .media_devices()
                .map_err(|_| CaptureError::DeviceNotAvailable("no media devices"))?;

            let constraints = MediaStreamConstraints::new();
            constraints.set_video(&JsValue::from(true));

            let promise = media
                .get_user_media_with_constraints(&constraints)
                .map_err(|_| CaptureError::PermissionDenied)?;

            let stream: MediaStream = JsFuture::from(promise)
                .await
                .map_err(|_| CaptureError::PermissionDenied)?
                .dyn_into()
                .map_err(|_| CaptureError::DeviceNotAvailable("expected MediaStream"))?;

            let video = doc
                .create_element("video")
                .map_err(|_| CaptureError::DeviceNotAvailable("cannot create video"))?
                .dyn_into::<web_sys::HtmlVideoElement>()
                .map_err(|_| CaptureError::DeviceNotAvailable("not a video element"))?;
            video.set_src_object(Some(&stream));
            video.set_autoplay(true);
            video.set_width(self.width);
            video.set_height(self.height);
            let _ = video.play();

            let canvas = doc
                .create_element("canvas")
                .map_err(|_| CaptureError::DeviceNotAvailable("cannot create canvas"))?
                .dyn_into::<HtmlCanvasElement>()
                .map_err(|_| CaptureError::DeviceNotAvailable("not a canvas element"))?;
            canvas.set_width(self.width);
            canvas.set_height(self.height);

            self.stream = Some(stream);
            self.video = Some(video);
            self.canvas = Some(canvas);
            Ok(())
        }
    }

    impl Capture for WebcamCapture {
        fn modality(&self) -> Modality {
            self.modality
        }

        fn capture(&mut self) -> Result<RawCapture, CaptureError> {
            let video = self
                .video
                .as_ref()
                .ok_or(CaptureError::DeviceNotAvailable("stream not started"))?;
            let canvas = self
                .canvas
                .as_ref()
                .ok_or(CaptureError::DeviceNotAvailable("no canvas"))?;

            let ctx = canvas
                .get_context("2d")
                .map_err(|_| CaptureError::DeviceNotAvailable("no 2d context"))?
                .ok_or(CaptureError::DeviceNotAvailable("no 2d context"))?
                .dyn_into::<web_sys::CanvasRenderingContext2d>()
                .map_err(|_| CaptureError::DeviceNotAvailable("not a 2d context"))?;

            ctx.draw_image_with_html_video_element(video, 0.0, 0.0)
                .map_err(|_| CaptureError::DeviceNotAvailable("draw_image failed"))?;

            let image_data = ctx
                .get_image_data(0.0, 0.0, self.width as f64, self.height as f64)
                .map_err(|_| CaptureError::DeviceNotAvailable("get_image_data failed"))?;

            let data = image_data.data().to_vec();
            let ts = js_sys::Date::now() as u64;

            Ok(RawCapture {
                meta: CaptureMeta {
                    modality: self.modality,
                    width: self.width,
                    height: self.height,
                    sample_rate: 0,
                    timestamp_ms: ts,
                    duration_ms: 33,
                },
                data,
            })
        }
    }

    impl Drop for WebcamCapture {
        fn drop(&mut self) {
            if let Some(stream) = &self.stream {
                for track in stream.get_tracks() {
                    if let Some(t) = track.dyn_ref::<MediaStreamTrack>() {
                        t.stop();
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // MicCapture — voice
    // -----------------------------------------------------------------------
    pub struct MicCapture {
        chunks: Rc<RefCell<Vec<Vec<u8>>>>,
        sample_rate: u32,
        _stream: Option<MediaStream>,
        _recorder: Option<MediaRecorder>,
        _data_closure: Option<Closure<dyn FnMut(BlobEvent)>>,
    }

    impl MicCapture {
        pub fn new() -> Self {
            Self {
                chunks: Rc::new(RefCell::new(Vec::new())),
                sample_rate: 48000,
                _stream: None,
                _recorder: None,
                _data_closure: None,
            }
        }

        pub async fn start_recording(&mut self) -> Result<(), CaptureError> {
            let win = window().ok_or(CaptureError::DeviceNotAvailable("no window"))?;
            let nav = win.navigator();
            let media = nav
                .media_devices()
                .map_err(|_| CaptureError::DeviceNotAvailable("no media devices"))?;

            let constraints = MediaStreamConstraints::new();
            constraints.set_audio(&JsValue::from(true));

            let promise = media
                .get_user_media_with_constraints(&constraints)
                .map_err(|_| CaptureError::PermissionDenied)?;
            let stream: MediaStream = JsFuture::from(promise)
                .await
                .map_err(|_| CaptureError::PermissionDenied)?
                .dyn_into()
                .map_err(|_| CaptureError::DeviceNotAvailable("expected MediaStream"))?;

            let recorder = MediaRecorder::new_with_media_stream(&stream)
                .map_err(|_| CaptureError::DeviceNotAvailable("MediaRecorder not supported"))?;

            let chunks = Rc::clone(&self.chunks);
            let data_closure = Closure::wrap(Box::new(move |event: BlobEvent| {
                let blob = match event.data() {
                    Some(b) => b,
                    None => return,
                };
                let chunks = Rc::clone(&chunks);
                let promise = blob.array_buffer();
                let future = JsFuture::from(promise);
                spawn_local(async move {
                    if let Ok(val) = future.await {
                        if let Some(buf) = val.dyn_ref::<js_sys::ArrayBuffer>() {
                            let uint8 = Uint8Array::new(buf);
                            let mut bytes = vec![0u8; uint8.length() as usize];
                            uint8.copy_to(&mut bytes);
                            if let Ok(mut guard) = chunks.try_borrow_mut() {
                                guard.push(bytes);
                            }
                        }
                    }
                });
            }) as Box<dyn FnMut(BlobEvent)>);
            recorder.set_ondataavailable(Some(data_closure.as_ref().unchecked_ref()));
            self._data_closure = Some(data_closure);

            recorder
                .start_with_time_slice(1000)
                .map_err(|_| CaptureError::DeviceNotAvailable("recorder start failed"))?;
            self._recorder = Some(recorder);
            self._stream = Some(stream);

            Ok(())
        }
    }

    impl Capture for MicCapture {
        fn modality(&self) -> Modality {
            Modality::Voice
        }
        fn capture(&mut self) -> Result<RawCapture, CaptureError> {
            let ts = js_sys::Date::now() as u64;
            let data = self.chunks.borrow().concat();
            let duration_ms = if self.sample_rate > 0 {
                (data.len() as u32 * 1000) / (self.sample_rate * 2)
            } else {
                0
            };
            Ok(RawCapture {
                meta: CaptureMeta {
                    modality: Modality::Voice,
                    width: 0,
                    height: 0,
                    sample_rate: self.sample_rate,
                    timestamp_ms: ts,
                    duration_ms,
                },
                data,
            })
        }
    }

    // -----------------------------------------------------------------------
    // KeyListener — keystroke dynamics (passive)
    // -----------------------------------------------------------------------
    pub struct KeyListener {
        buffer: Rc<RefCell<Vec<KeyEvent>>>,
        key_state: Rc<RefCell<Vec<(u32, u64)>>>,
        _down_closure: Option<Closure<dyn Fn(KeyboardEvent)>>,
        _up_closure: Option<Closure<dyn Fn(KeyboardEvent)>>,
    }

    impl KeyListener {
        pub fn new() -> Self {
            Self {
                buffer: Rc::new(RefCell::new(Vec::new())),
                key_state: Rc::new(RefCell::new(Vec::new())),
                _down_closure: None,
                _up_closure: None,
            }
        }

        pub fn attach(&mut self) -> Result<(), CaptureError> {
            let doc = document().ok_or(CaptureError::DeviceNotAvailable("no document"))?;
            let buffer = Rc::clone(&self.buffer);
            let key_state = Rc::clone(&self.key_state);

            let ks = Rc::clone(&key_state);
            let down = Closure::<dyn Fn(KeyboardEvent)>::new(move |event: KeyboardEvent| {
                event.prevent_default();
                let code = event.key_code();
                let now = js_sys::Date::now() as u64;
                if let Ok(mut state) = ks.try_borrow_mut() {
                    state.push((code, now));
                }
            });
            doc.add_event_listener_with_callback("keydown", down.as_ref().unchecked_ref())
                .map_err(|_| CaptureError::NotSupported("keydown listener failed"))?;

            let buf = Rc::clone(&buffer);
            let ks2 = Rc::clone(&key_state);
            let up = Closure::<dyn Fn(KeyboardEvent)>::new(move |event: KeyboardEvent| {
                let code = event.key_code();
                let release = js_sys::Date::now() as u64;
                if let Ok(mut state) = ks2.try_borrow_mut() {
                    if let Some(pos) = state.iter().position(|(c, _)| *c == code) {
                        let (_, press) = state.remove(pos);
                        let ev = KeyEvent {
                            key_code: code,
                            press_time_ms: press,
                            release_time_ms: release,
                        };
                        if let Ok(mut b) = buf.try_borrow_mut() {
                            b.push(ev);
                        }
                    }
                }
            });
            doc.add_event_listener_with_callback("keyup", up.as_ref().unchecked_ref())
                .map_err(|_| CaptureError::NotSupported("keyup listener failed"))?;

            self._down_closure = Some(down);
            self._up_closure = Some(up);
            Ok(())
        }
    }

    impl Capture for KeyListener {
        fn modality(&self) -> Modality {
            Modality::Keystroke
        }

        fn capture(&mut self) -> Result<RawCapture, CaptureError> {
            let ts = js_sys::Date::now() as u64;
            let events = self.buffer.take();
            let mut data = Vec::with_capacity(events.len() * 20);
            for ev in &events {
                data.extend_from_slice(&ev.key_code.to_le_bytes());
                data.extend_from_slice(&ev.press_time_ms.to_le_bytes());
                data.extend_from_slice(&ev.release_time_ms.to_le_bytes());
            }
            Ok(RawCapture {
                meta: CaptureMeta {
                    modality: Modality::Keystroke,
                    width: 0,
                    height: 0,
                    sample_rate: 0,
                    timestamp_ms: ts,
                    duration_ms: 0,
                },
                data,
            })
        }
    }

    // -----------------------------------------------------------------------
    // TouchListener — touch gesture dynamics (passive)
    // -----------------------------------------------------------------------
    pub struct TouchListener {
        buffer: Rc<RefCell<Vec<u8>>>,
        _start_closure: Option<Closure<dyn Fn(TouchEvent)>>,
        _end_closure: Option<Closure<dyn Fn(TouchEvent)>>,
    }

    impl TouchListener {
        pub fn new() -> Self {
            Self {
                buffer: Rc::new(RefCell::new(Vec::new())),
                _start_closure: None,
                _end_closure: None,
            }
        }

        pub fn attach(&mut self) -> Result<(), CaptureError> {
            let doc = document().ok_or(CaptureError::DeviceNotAvailable("no document"))?;
            let buf = Rc::clone(&self.buffer);

            let start = Closure::<dyn Fn(TouchEvent)>::new(move |e: TouchEvent| {
                e.prevent_default();
                let touches = TouchEvent::changed_touches(&e);
                for i in 0..TouchList::length(&touches) {
                    if let Some(touch) = TouchList::item(&touches, i) {
                        let x = Touch::client_x(&touch) as f32;
                        let y = Touch::client_y(&touch) as f32;
                        let pressure = Touch::force(&touch);
                        let ts = js_sys::Date::now() as u64;
                        if let Ok(mut b) = buf.try_borrow_mut() {
                            b.extend_from_slice(&x.to_le_bytes());
                            b.extend_from_slice(&y.to_le_bytes());
                            b.extend_from_slice(&pressure.to_le_bytes());
                            b.extend_from_slice(&ts.to_le_bytes());
                        }
                    }
                }
            });
            doc.add_event_listener_with_callback("touchstart", start.as_ref().unchecked_ref())
                .map_err(|_| CaptureError::NotSupported("touch listener failed"))?;

            self._start_closure = Some(start);
            self._end_closure = None;
            Ok(())
        }
    }

    impl Capture for TouchListener {
        fn modality(&self) -> Modality {
            Modality::TouchGesture
        }
        fn capture(&mut self) -> Result<RawCapture, CaptureError> {
            let data = self.buffer.take();
            Ok(RawCapture {
                meta: CaptureMeta {
                    modality: Modality::TouchGesture,
                    width: 0,
                    height: 0,
                    sample_rate: 0,
                    timestamp_ms: js_sys::Date::now() as u64,
                    duration_ms: 0,
                },
                data,
            })
        }
    }

    // -----------------------------------------------------------------------
    // MotionSensor — gait analysis (passive)
    // -----------------------------------------------------------------------
    pub struct MotionSensor {
        buffer: Rc<RefCell<Vec<u8>>>,
        _motion_closure: Option<Closure<dyn Fn(DeviceMotionEvent)>>,
    }

    impl MotionSensor {
        pub fn new() -> Self {
            Self {
                buffer: Rc::new(RefCell::new(Vec::new())),
                _motion_closure: None,
            }
        }

        pub fn attach(&mut self) -> Result<(), CaptureError> {
            let win = window().ok_or(CaptureError::DeviceNotAvailable("no window"))?;
            let buf = Rc::clone(&self.buffer);

            let motion = Closure::<dyn Fn(DeviceMotionEvent)>::new(move |e: DeviceMotionEvent| {
                let accel = DeviceMotionEvent::acceleration_including_gravity(&e);
                if let Some(a) = accel {
                    let x = DeviceAcceleration::x(&a).unwrap_or(0.0) as f32;
                    let y = DeviceAcceleration::y(&a).unwrap_or(0.0) as f32;
                    let z = DeviceAcceleration::z(&a).unwrap_or(0.0) as f32;
                    if let Ok(mut b) = buf.try_borrow_mut() {
                        b.extend_from_slice(&x.to_le_bytes());
                        b.extend_from_slice(&y.to_le_bytes());
                        b.extend_from_slice(&z.to_le_bytes());
                    }
                }
            });
            win.add_event_listener_with_callback("devicemotion", motion.as_ref().unchecked_ref())
                .map_err(|_| CaptureError::NotSupported("devicemotion listener failed"))?;

            self._motion_closure = Some(motion);
            Ok(())
        }
    }

    impl Capture for MotionSensor {
        fn modality(&self) -> Modality {
            Modality::Gait
        }
        fn capture(&mut self) -> Result<RawCapture, CaptureError> {
            let data = self.buffer.take();
            Ok(RawCapture {
                meta: CaptureMeta {
                    modality: Modality::Gait,
                    width: 0,
                    height: 0,
                    sample_rate: 0,
                    timestamp_ms: js_sys::Date::now() as u64,
                    duration_ms: 0,
                },
                data,
            })
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------
    fn document() -> Option<Document> {
        window()?.document()
    }
}

// ---------------------------------------------------------------------------
// Mock data generator for testing and integration demos
// ---------------------------------------------------------------------------
pub struct MockCapture {
    pub modality: Modality,
    counter: u64,
    data_override: Option<Vec<u8>>,
}

impl MockCapture {
    pub fn new(modality: Modality) -> Self {
        Self {
            modality,
            counter: 0,
            data_override: None,
        }
    }

    /// Create a mock capture that returns the given raw data verbatim.
    pub fn with_data(modality: Modality, data: Vec<u8>) -> Self {
        Self {
            modality,
            counter: 0,
            data_override: Some(data),
        }
    }
}

impl Capture for MockCapture {
    fn modality(&self) -> Modality {
        self.modality
    }
    fn capture(&mut self) -> Result<RawCapture, CaptureError> {
        self.counter += 1;
        let data = if let Some(ref d) = self.data_override {
            d.clone()
        } else {
            match self.modality {
                Modality::Face | Modality::Iris => {
                    // 32×32 RGBA dummy image
                    vec![0x80u8; 32 * 32 * 4]
                }
                Modality::Voice => {
                    // 1 second of 8 kHz i16 PCM
                    vec![0u8; 8000 * 2]
                }
                Modality::Fingerprint => {
                    vec![0u8; 256]
                }
                Modality::Keystroke => {
                    let mut data = Vec::with_capacity(10 * 24);
                    for i in 0..10u32 {
                        let ev = KeyEvent {
                            key_code: 65 + i,
                            press_time_ms: self.counter * 1000 + i as u64 * 80,
                            release_time_ms: self.counter * 1000 + i as u64 * 80 + 60,
                        };
                        data.extend_from_slice(&ev.key_code.to_le_bytes());
                        data.extend_from_slice(&ev.press_time_ms.to_le_bytes());
                        data.extend_from_slice(&ev.release_time_ms.to_le_bytes());
                    }
                    data
                }
                Modality::TouchGesture => {
                    let mut data = Vec::with_capacity(20 * 20);
                    for i in 0..20u32 {
                        let ev = TouchEvent {
                            x: (i as f32) * 10.0,
                            y: (i as f32) * 5.0,
                            pressure: 0.5,
                            time_ms: self.counter * 1000 + i as u64 * 16,
                        };
                        data.extend_from_slice(&ev.x.to_le_bytes());
                        data.extend_from_slice(&ev.y.to_le_bytes());
                        data.extend_from_slice(&ev.pressure.to_le_bytes());
                        data.extend_from_slice(&ev.time_ms.to_le_bytes());
                    }
                    data
                }
                Modality::Gait => {
                    let mut data = Vec::with_capacity(128 * 16);
                    for i in 0..128u32 {
                        let f = AccelFrame {
                            x: libm::sinf((i as f32) * 0.1),
                            y: libm::cosf((i as f32) * 0.1),
                            z: -9.8,
                            time_ms: self.counter * 1000 + i as u64 * 10,
                        };
                        data.extend_from_slice(&f.x.to_le_bytes());
                        data.extend_from_slice(&f.y.to_le_bytes());
                        data.extend_from_slice(&f.z.to_le_bytes());
                        data.extend_from_slice(&f.time_ms.to_le_bytes());
                    }
                    data
                }
            }
        };

        Ok(RawCapture {
            meta: CaptureMeta {
                modality: self.modality,
                width: if matches!(self.modality, Modality::Face) {
                    32
                } else {
                    0
                },
                height: if matches!(self.modality, Modality::Face) {
                    32
                } else {
                    0
                },
                sample_rate: if matches!(self.modality, Modality::Voice) {
                    8000
                } else {
                    0
                },
                timestamp_ms: (self.counter + 1) * 1000,
                duration_ms: 500,
            },
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_empty_data() {
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Face,
                width: 32,
                height: 32,
                sample_rate: 0,
                timestamp_ms: 1_700_000_000_000,
                duration_ms: 0,
            },
            data: vec![],
        };
        assert_eq!(cap.validate(), Err(CaptureError::InsufficientData));
    }

    #[test]
    fn validate_rejects_zero_timestamp() {
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Face,
                width: 32,
                height: 32,
                sample_rate: 0,
                timestamp_ms: 0,
                duration_ms: 0,
            },
            data: vec![0x80; 32 * 32 * 4],
        };
        assert_eq!(
            cap.validate(),
            Err(CaptureError::InvalidMetadata("timestamp_ms is 0"))
        );
    }

    #[test]
    fn validate_rejects_image_with_zero_dimensions() {
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Face,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: 1_700_000_000_000,
                duration_ms: 0,
            },
            data: vec![0x80; 100],
        };
        assert_eq!(
            cap.validate(),
            Err(CaptureError::InvalidMetadata("image width/height is 0"))
        );
    }

    #[test]
    fn validate_rejects_audio_with_zero_sample_rate() {
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Voice,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: 1_700_000_000_000,
                duration_ms: 0,
            },
            data: vec![0x00; 1024],
        };
        assert_eq!(
            cap.validate(),
            Err(CaptureError::InvalidMetadata("sample_rate is 0 for audio"))
        );
    }

    #[test]
    fn validate_passes_valid_image() {
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Face,
                width: 32,
                height: 32,
                sample_rate: 0,
                timestamp_ms: 1_700_000_000_000,
                duration_ms: 0,
            },
            data: vec![0x80; 32 * 32 * 4],
        };
        assert!(cap.validate().is_ok());
    }

    #[test]
    fn validate_rejects_implausible_timestamp() {
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Face,
                width: 32,
                height: 32,
                sample_rate: 0,
                timestamp_ms: 1000,
                duration_ms: 0,
            },
            data: vec![0x80; 32 * 32 * 4],
        };
        assert_eq!(
            cap.validate(),
            Err(CaptureError::InvalidMetadata(
                "timestamp_ms before 2000-01-01 (implausible)"
            ))
        );
    }

    #[test]
    fn validate_rejects_future_timestamp_beyond_skew() {
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Face,
                width: 32,
                height: 32,
                sample_rate: 0,
                timestamp_ms: 1_700_000_000_000 + MAX_CLOCK_SKEW_MS + 1,
                duration_ms: 0,
            },
            data: vec![0x80; 32 * 32 * 4],
        };
        assert_eq!(
            cap.validate_at(1_700_000_000_000),
            Err(CaptureError::InvalidMetadata("timestamp_ms is in the future"))
        );
    }

    #[test]
    fn validate_accepts_timestamp_within_skew() {
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Face,
                width: 32,
                height: 32,
                sample_rate: 0,
                timestamp_ms: 1_700_000_000_000 + MAX_CLOCK_SKEW_MS,
                duration_ms: 0,
            },
            data: vec![0x80; 32 * 32 * 4],
        };
        assert!(cap.validate_at(1_700_000_000_000).is_ok());
    }

    #[test]
    fn validate_passes_valid_non_visual_modality() {
        let cap = RawCapture {
            meta: CaptureMeta {
                modality: Modality::Keystroke,
                width: 0,
                height: 0,
                sample_rate: 0,
                timestamp_ms: 1_700_000_000_000,
                duration_ms: 0,
            },
            data: vec![0x00; 64],
        };
        assert!(cap.validate().is_ok());
    }
}
