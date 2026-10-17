//! A string that must never be printed or logged.

use std::fmt;

/// A secret value such as a `.p12` password or an App Store Connect private
/// key. `Debug` output is redacted and there is deliberately no `Display` or
/// `Serialize` implementation.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the secret value. Only call this where the value is consumed
    /// (decrypting a key, signing a token), never to print it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new("hunter2");
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
        assert_eq!(secret.expose(), "hunter2");
    }
}
