use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum SdkError {
    MatrixDimensionMismatch { expected: usize, got: usize },
    VectorDimensionMismatch { expected: usize, got: usize },
    InvalidSeed,
    CryptoError { reason: &'static str },
    ModalityNotSupported(&'static str),
    ModalitySelectionTooFew { got: usize, min: usize },
    ExtractionFailed(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CaptureError {
    NotSupported(&'static str),
    DeviceNotAvailable(&'static str),
    PermissionDenied,
    Timeout,
    InsufficientData,
    InvalidMetadata(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtractionError {
    ModelNotLoaded(&'static str),
    InsufficientData,
    InvalidFormat,
    DimensionMismatch { expected: usize, got: usize },
    OnnxLoad(String),
    OnnxInfer(String),
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdkError::MatrixDimensionMismatch { expected, got } => {
                write!(
                    f,
                    "matrix dimension mismatch: expected {expected}, got {got}"
                )
            }
            SdkError::VectorDimensionMismatch { expected, got } => {
                write!(
                    f,
                    "vector dimension mismatch: expected {expected}, got {got}"
                )
            }
            SdkError::InvalidSeed => write!(f, "invalid projection seed"),
            SdkError::CryptoError { reason } => write!(f, "crypto error: {reason}"),
            SdkError::ModalityNotSupported(m) => write!(f, "modality not supported: {m}"),
            SdkError::ModalitySelectionTooFew { got, min } => {
                write!(f, "need at least {min} modalities, got {got}")
            }
            SdkError::ExtractionFailed(reason) => write!(f, "extraction failed: {reason}"),
        }
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::NotSupported(m) => write!(f, "capture not supported: {m}"),
            CaptureError::DeviceNotAvailable(m) => write!(f, "device not available: {m}"),
            CaptureError::PermissionDenied => write!(f, "permission denied"),
            CaptureError::Timeout => write!(f, "capture timeout"),
            CaptureError::InsufficientData => write!(f, "insufficient capture data"),
            CaptureError::InvalidMetadata(msg) => write!(f, "invalid capture metadata: {msg}"),
        }
    }
}

impl fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractionError::ModelNotLoaded(m) => write!(f, "ML model not loaded: {m}"),
            ExtractionError::InsufficientData => write!(f, "insufficient data for extraction"),
            ExtractionError::InvalidFormat => write!(f, "invalid capture format"),
            ExtractionError::DimensionMismatch { expected, got } => {
                write!(f, "dimension mismatch: expected {expected}, got {got}")
            }
            ExtractionError::OnnxLoad(msg) => write!(f, "ONNX load error: {msg}"),
            ExtractionError::OnnxInfer(msg) => write!(f, "ONNX inference error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SdkError {}

#[cfg(feature = "std")]
impl std::error::Error for CaptureError {}

#[cfg(feature = "std")]
impl std::error::Error for ExtractionError {}
