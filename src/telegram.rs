//! Fire-and-forget Telegram notifications, carried over from mc-runner:
//! start, stop, join and leave announcements plus exit status reports.
//!
//! The bot token doubles as the login provider credential: the login widget
//! hands the page a signed statement of identity, and [`verify_login_payload`]
//! checks its HMAC against this token.

use std::sync::OnceLock;
use std::time::Duration;

use hmac::Hmac;
use hmac::Mac;
use reqwest::Client;
use sha2::Digest;
use sha2::Sha256;
use tracing::error;

use crate::config::TelegramConfig;

/// Total request timeout, same as mc-runner's http client.
const TELEGRAM_TIMEOUT: Duration = Duration::from_secs(10);

/// The shared http client, built once per process. A build failure is cached
/// as `None` so a broken environment neither panics nor retries on every
/// message.
fn shared_client() -> Option<&'static Client> {
    static CLIENT: OnceLock<Option<Client>> = OnceLock::new();
    CLIENT
        .get_or_init(
            || match Client::builder().timeout(TELEGRAM_TIMEOUT).build() {
                Ok(client) => Some(client),
                Err(source) => {
                    error!("could not build the telegram http client: {source}");
                    None
                }
            },
        )
        .as_ref()
}

/// Send `message` to every configured chat id, fire and forget.
///
/// A no-op when the token or the chat id list is empty. Each chat gets its
/// own task so one slow chat cannot delay the others. Failures are logged
/// and never propagated: notifications must not be able to take the runner
/// down.
pub fn send_message(config: &TelegramConfig, message: &str) {
    if config.token.is_empty() || config.chat_ids.is_empty() {
        return;
    }
    let Some(client) = shared_client() else {
        return;
    };
    for chat_id in config.chat_ids() {
        let client = client.clone();
        let chat_id = chat_id.to_string();
        let message = message.to_string();
        let url = format!("https://api.telegram.org/bot{}/sendMessage", config.token);
        tokio::spawn(async move {
            let payload = serde_json::json!({ "chat_id": chat_id, "text": message });
            match client.post(&url).json(&payload).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.as_u16() != 200 {
                        error!(
                            status = status.as_u16(),
                            "telegram api returned non-200 status"
                        );
                    }
                }
                Err(source) => error!("failed to send telegram message: {source}"),
            }
        });
    }
}

/// How long a widget payload stays fresh. The browser posts the callback
/// right after the widget hands it over, and the protocol has no nonce, so
/// this timestamp is the only replay bound.
pub const LOGIN_PAYLOAD_MAX_AGE_SECS: i64 = 5 * 60;

/// A verified telegram login: the identity fields the runner keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginIdentity {
    /// The numeric telegram account id; the only stable claim.
    pub telegram_id: i64,
    /// Display name from the profile (`first_name`, extended by
    /// `last_name` when present).
    pub name: Option<String>,
    /// The @handle, absent when the account hides it.
    pub username: Option<String>,
    /// Profile picture url, if the account exposes one.
    pub photo_url: Option<String>,
}

/// Why a login payload was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LoginVerifyError {
    /// The payload is not shaped like a widget callback at all.
    #[error("malformed login payload")]
    Malformed,
    /// The signature does not match the payload for this bot.
    #[error("invalid login payload signature")]
    BadSignature,
    /// The payload is older than [`LOGIN_PAYLOAD_MAX_AGE_SECS`].
    #[error("login payload is stale")]
    Stale,
}

/// Verify a telegram login widget payload against the bot token.
///
/// `payload` is the raw JSON object exactly as the widget handed it to the
/// page, so the check string covers precisely the fields Telegram signed:
/// every field except `hash`, sorted alphabetically, written as `key=value`
/// and joined with newlines. The HMAC key is the SHA-256 of the bot token,
/// and `hash` must equal the lowercase hex digest. The payload's `auth_date`
/// must be at most [`LOGIN_PAYLOAD_MAX_AGE_SECS`] seconds old.
pub fn verify_login_payload(
    payload: &serde_json::Map<String, serde_json::Value>,
    bot_token: &str,
    now: i64,
) -> Result<LoginIdentity, LoginVerifyError> {
    let mut hash_hex = None;
    let mut pairs: Vec<(&str, String)> = Vec::with_capacity(payload.len());
    for (key, value) in payload {
        let rendered = match value {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Number(number) => number.to_string(),
            // Booleans, arrays and nested objects never appear in a widget
            // payload; anything else means this is not one.
            _ => return Err(LoginVerifyError::Malformed),
        };
        if key == "hash" {
            hash_hex = Some(rendered);
        } else {
            pairs.push((key.as_str(), rendered));
        }
    }
    let hash_hex = hash_hex.ok_or(LoginVerifyError::Malformed)?;

    let secret = Sha256::digest(bot_token.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret)
        .map_err(|_hmac_error| LoginVerifyError::Malformed)?;
    pairs.sort_unstable_by_key(|(key, _)| *key);
    let check = pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");
    mac.update(check.as_bytes());
    let expected = mac.finalize().into_bytes();
    let provided = hex_decode(&hash_hex).ok_or(LoginVerifyError::BadSignature)?;
    if !constant_time_eq(&expected, &provided) {
        return Err(LoginVerifyError::BadSignature);
    }

    let auth_date = field_i64(payload, "auth_date").ok_or(LoginVerifyError::Malformed)?;
    let age = now.saturating_sub(auth_date);
    if age > LOGIN_PAYLOAD_MAX_AGE_SECS || now.saturating_sub(auth_date) < -60 {
        return Err(LoginVerifyError::Stale);
    }
    let telegram_id = field_i64(payload, "id").ok_or(LoginVerifyError::Malformed)?;

    let name = profile_name(payload);
    let username = payload
        .get("username")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let photo_url = payload
        .get("photo_url")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    Ok(LoginIdentity {
        telegram_id,
        name,
        username,
        photo_url,
    })
}

/// Read a signed integer field that may arrive as a JSON number or as the
/// same value wrapped in a string.
fn field_i64(payload: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<i64> {
    match payload.get(key)? {
        serde_json::Value::Number(number) => number.as_i64(),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

/// Display name: `first_name`, extended by `last_name` when present.
fn profile_name(payload: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    let first = payload
        .get("first_name")
        .and_then(serde_json::Value::as_str);
    let last = payload.get("last_name").and_then(serde_json::Value::as_str);
    match (first, last) {
        (Some(first), Some(last)) => Some(format!("{first} {last}")),
        (Some(first), None) => Some(first.to_string()),
        (None, Some(last)) => Some(last.to_string()),
        (None, None) => None,
    }
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let high = pair
                .first()
                .copied()
                .and_then(|byte| char::from(byte).to_digit(16))?;
            let low = pair
                .get(1)
                .copied()
                .and_then(|byte| char::from(byte).to_digit(16))?;
            let value = high.checked_mul(16)?.checked_add(low)?;
            u8::try_from(value).ok()
        })
        .collect()
}

/// Length-independent byte comparison, so a forged hash cannot probe the
/// digest byte by byte through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Lowercase hex, used to build the signature test vectors.
#[cfg(test)]
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::send_message;
    use super::*;
    use crate::config::TelegramConfig;
    use serde_json::json;

    const BOT_TOKEN: &str = "12345:test-bot-token";

    /// Sign `fields` exactly the way Telegram does, returning the payload
    /// with its `hash` field.
    fn signed_payload(fields: serde_json::Value) -> serde_json::Value {
        let object = fields.as_object().expect("fields must be an object");
        let mut pairs: Vec<(&str, String)> = object
            .iter()
            .map(|(key, value)| match value {
                serde_json::Value::String(text) => (key.as_str(), text.clone()),
                serde_json::Value::Number(number) => (key.as_str(), number.to_string()),
                _ => panic!("test fields must be strings or numbers"),
            })
            .collect();
        pairs.sort_unstable_by_key(|(key, _)| *key);
        let check = pairs
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("\n");
        let secret = Sha256::digest(BOT_TOKEN.as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("hmac key");
        mac.update(check.as_bytes());
        let mut payload = fields;
        payload
            .as_object_mut()
            .expect("fields must be an object")
            .insert(
                String::from("hash"),
                serde_json::Value::String(hex_encode(&mac.finalize().into_bytes())),
            );
        payload
    }

    fn payload_now() -> serde_json::Value {
        signed_payload(json!({
            "id": 42,
            "first_name": "Alice",
            "username": "alice",
            "auth_date": crate::clock::unix_now(),
        }))
    }

    #[test]
    fn chat_ids_split_trim_and_skip_empties() {
        let config = TelegramConfig {
            token: "tok".to_string(),
            username: String::new(),
            chat_ids: " 1 ;2;;; 3 ; 4 ".to_string(),
        };
        let ids: Vec<&str> = config.chat_ids().collect();
        assert_eq!(ids, vec!["1", "2", "3", "4"], "trimmed non-empty ids");
        assert_eq!(config.chat_id_count(), 4, "count agrees with the iterator");
    }

    #[test]
    fn chat_ids_of_empty_config_is_empty() {
        let config = TelegramConfig::default();
        assert!(
            config.chat_ids().next().is_none(),
            "no ids should come out of an empty list"
        );
        assert_eq!(config.chat_id_count(), 0, "empty config has zero ids");
    }

    #[test]
    fn send_message_without_token_is_a_no_op() {
        let config = TelegramConfig {
            token: String::new(),
            username: String::new(),
            chat_ids: "1;2".to_string(),
        };
        send_message(&config, "Server test starting...");
    }

    #[test]
    fn send_message_without_chat_ids_is_a_no_op() {
        let config = TelegramConfig {
            token: "tok".to_string(),
            username: String::new(),
            chat_ids: String::new(),
        };
        send_message(&config, "Server test stopping...");
    }

    #[test]
    fn valid_payload_verifies_and_yields_the_identity() {
        let payload = payload_now();
        let identity = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        )
        .unwrap_or_else(|err| panic!("signed payload should verify: {err}"));
        assert_eq!(identity.telegram_id, 42);
        assert_eq!(identity.name.as_deref(), Some("Alice"));
        assert_eq!(identity.username.as_deref(), Some("alice"));
        assert_eq!(identity.photo_url, None);
    }

    #[test]
    fn last_name_extends_the_display_name() {
        let payload = signed_payload(json!({
            "id": 7,
            "first_name": "Bob",
            "last_name": "Tables",
            "auth_date": crate::clock::unix_now(),
        }));
        let identity = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        )
        .unwrap_or_else(|err| panic!("payload should verify: {err}"));
        assert_eq!(identity.name.as_deref(), Some("Bob Tables"));
        assert_eq!(identity.username, None);
    }

    #[test]
    fn tampered_fields_break_the_signature() {
        let mut payload = payload_now();
        payload["username"] = json!("mallory");
        let result = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        );
        assert_eq!(result, Err(LoginVerifyError::BadSignature));
    }

    #[test]
    fn a_foreign_bot_token_breaks_the_signature() {
        let payload = payload_now();
        let result = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            "12345:another-bot",
            crate::clock::unix_now(),
        );
        assert_eq!(result, Err(LoginVerifyError::BadSignature));
    }

    #[test]
    fn stale_payloads_are_rejected() {
        let old = crate::clock::unix_now() - (LOGIN_PAYLOAD_MAX_AGE_SECS + 10);
        let payload = signed_payload(json!({ "id": 1, "auth_date": old }));
        let result = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        );
        assert_eq!(result, Err(LoginVerifyError::Stale));
    }

    #[test]
    fn payload_from_the_future_is_rejected() {
        let future = crate::clock::unix_now() + 3600;
        let payload = signed_payload(json!({ "id": 1, "auth_date": future }));
        let result = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        );
        assert_eq!(result, Err(LoginVerifyError::Stale));
    }

    #[test]
    fn missing_or_non_hex_hash_is_a_bad_signature() {
        let payload = json!({ "id": 1, "auth_date": crate::clock::unix_now() });
        let result = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        );
        assert_eq!(result, Err(LoginVerifyError::Malformed));

        let payload = json!({
            "id": 1,
            "auth_date": crate::clock::unix_now(),
            "hash": "not hex at all!",
        });
        let result = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        );
        assert_eq!(result, Err(LoginVerifyError::BadSignature));
    }

    #[test]
    fn non_scalar_fields_are_malformed() {
        let payload = json!({
            "id": 1,
            "auth_date": crate::clock::unix_now(),
            "weird": ["a", "b"],
        });
        let result = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        );
        assert_eq!(result, Err(LoginVerifyError::Malformed));
    }

    #[test]
    fn missing_id_or_auth_date_is_malformed() {
        let payload = signed_payload(json!({ "auth_date": crate::clock::unix_now() }));
        let result = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        );
        assert_eq!(result, Err(LoginVerifyError::Malformed));

        let payload = signed_payload(json!({ "id": 1 }));
        let result = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        );
        assert_eq!(result, Err(LoginVerifyError::Malformed));
    }

    #[test]
    fn id_as_string_is_accepted() {
        // Some clients serialize the id as a string; the signed rendering is
        // identical, so verification must accept both.
        let payload = signed_payload(json!({
            "id": "42",
            "auth_date": crate::clock::unix_now(),
        }));
        let identity = verify_login_payload(
            payload.as_object().expect("payload is an object"),
            BOT_TOKEN,
            crate::clock::unix_now(),
        )
        .unwrap_or_else(|err| panic!("string id should verify: {err}"));
        assert_eq!(identity.telegram_id, 42);
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(
            hex_decode(&hex_encode(&[0xde, 0xad, 0xbe, 0xef])).as_deref(),
            Some(&[0xde, 0xad, 0xbe, 0xef][..])
        );
        assert_eq!(hex_decode(""), Some(Vec::new()));
        for bad in ["abc", "zz", "0g"] {
            assert_eq!(hex_decode(bad), None, "{bad:?} should not decode");
        }
    }

    #[test]
    fn constant_time_eq_agrees_with_slice_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
