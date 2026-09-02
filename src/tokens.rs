//! Opaque token machinery: generation, sharing and hashing.
//!
//! A token is 32 random bytes. It is shared as unpadded base64url and stored
//! in the database only as its SHA3-256 hash, matching mc-runner, so a
//! database leak does not leak usable credentials.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha3::{Digest, Sha3_256};

/// Length in bytes of the random part of every token.
const TOKEN_LENGTH: usize = 32;

/// The shared token could not be decoded as base64url.
#[derive(Debug, thiserror::Error)]
#[error("token is not valid base64url: {0}")]
pub struct InvalidToken(#[from] base64::DecodeError);

/// Generate a fresh token. Returns the base64url form to share and the
/// SHA3-256 hash to store. Infallible: the underlying OS random source is
/// treated as infallible by `rand` 0.9.
#[must_use]
pub fn generate_token() -> (String, [u8; TOKEN_LENGTH]) {
    let raw: [u8; TOKEN_LENGTH] = rand::random();
    (URL_SAFE_NO_PAD.encode(raw), sha3_256(&raw))
}

/// Hash a shared base64url token into its database form.
///
/// # Errors
/// Returns [`InvalidToken`] if the input is not valid unpadded base64url.
pub fn hash_from_b64(token: &str) -> Result<[u8; TOKEN_LENGTH], InvalidToken> {
    let raw = URL_SAFE_NO_PAD.decode(token)?;
    Ok(sha3_256(&raw))
}

fn sha3_256(bytes: &[u8]) -> [u8; TOKEN_LENGTH] {
    Sha3_256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_from_b64_roundtrips_generate_token() {
        let (token_b64, hash) = generate_token();
        let rehashed = hash_from_b64(&token_b64)
            .unwrap_or_else(|err| panic!("own token should decode: {err}"));
        assert_eq!(rehashed, hash, "hashing the shared form must match");
    }

    #[test]
    fn malformed_base64_is_rejected() {
        for bad in ["!!!", "with spaces", "a/b=c"] {
            assert!(
                hash_from_b64(bad).is_err(),
                "malformed token {bad:?} should be rejected"
            );
        }
        // The empty string decodes to zero bytes, so it is technically valid
        // base64; it just never matches a stored token hash.
        assert!(hash_from_b64("").is_ok(), "empty input is valid base64");
    }

    #[test]
    fn hash_matches_the_sha3_256_test_vector() {
        // SHA3-256("abc"), from the NIST examples.
        let expected: [u8; 32] = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3,
            0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45,
            0x11, 0x43, 0x15, 0x32,
        ];
        let hash =
            hash_from_b64("YWJj").unwrap_or_else(|err| panic!("\"YWJj\" should decode: {err}"));
        assert_eq!(hash, expected, "SHA3-256(\"abc\") test vector");
    }

    #[test]
    fn different_tokens_hash_differently() {
        let (_, first) = generate_token();
        let (_, second) = generate_token();
        assert_ne!(first, second, "random tokens must not collide");
    }
}
