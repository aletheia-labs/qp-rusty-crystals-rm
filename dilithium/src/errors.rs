use core::fmt::Display;

#[derive(Debug)]
pub enum KeyParsingError {
    BadSecretKey,
    BadPublicKey,
    BadKeypair
}

impl Display for KeyParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            KeyParsingError::BadSecretKey => "BadSecretKey".to_string(),
            KeyParsingError::BadPublicKey => "BadPublicKey".to_string(),
            KeyParsingError::BadKeypair => "BadKeypair".to_string(),
        };
        write!(f, "{}", str)
    }
}

#[cfg(not(feature = "no_std"))]
impl std::error::Error for KeyParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}