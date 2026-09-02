//! Fire-and-forget Telegram notifications, carried over from mc-runner:
//! start, stop, join and leave announcements plus exit status reports.

use std::sync::OnceLock;
use std::time::Duration;

use reqwest::Client;
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

#[cfg(test)]
mod tests {
    use super::send_message;
    use crate::config::TelegramConfig;

    #[test]
    fn chat_ids_split_trim_and_skip_empties() {
        let config = TelegramConfig {
            token: "tok".to_string(),
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
            chat_ids: "1;2".to_string(),
        };
        send_message(&config, "Server test starting...");
    }

    #[test]
    fn send_message_without_chat_ids_is_a_no_op() {
        let config = TelegramConfig {
            token: "tok".to_string(),
            chat_ids: String::new(),
        };
        send_message(&config, "Server test stopping...");
    }
}
