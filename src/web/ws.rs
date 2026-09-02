//! The websocket feed, protocol-compatible with mc-runner:
//! on connect the full state and the chat history are sent, then every
//! broadcast is forwarded; text messages equal to `start` start the server.

use std::sync::Arc;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use tracing::{debug, error, warn};

use crate::server::Runner;
use crate::state::FeedMessage;
use crate::web::AppState;

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| handle_socket(state.runner, socket))
}

async fn handle_socket(runner: Arc<Runner>, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let mut state_rx = runner.subscribe_state();
    let mut chat_rx = runner.subscribe_chat();
    let mut shutdown_rx = runner.subscribe_shutdown();

    // Subscribe first, then snapshot: nothing can be missed in between.
    let initial_state = FeedMessage::State(Arc::unwrap_or_clone(runner.get_state()));
    if !send_message(&mut sink, &initial_state).await {
        return;
    }
    let history = FeedMessage::Chat(runner.chat_history());
    if !send_message(&mut sink, &history).await {
        return;
    }

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                debug!("websocket closing because the runner is shutting down");
                break;
            }
            update = state_rx.recv() => match update {
                Ok(state) => {
                    let message = FeedMessage::State(Arc::unwrap_or_clone(state));
                    if !send_message(&mut sink, &message).await {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    warn!("state feed lagged, {missed} updates lost, closing the connection");
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            update = chat_rx.recv() => match update {
                Ok(line) => {
                    let message = FeedMessage::Chat(line);
                    if !send_message(&mut sink, &message).await {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    warn!("chat feed lagged, {missed} lines lost, closing the connection");
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    if text.as_str() == "start"
                        && let Err(source) = runner.start().await
                    {
                        warn!("could not start the server: {source}");
                    }
                    // Any other text message is ignored, mc-runner parity.
                }
                Some(Ok(message)) => warn!("ignoring non-text websocket message: {message:?}"),
                Some(Err(source)) => {
                    debug!("websocket read error: {source}");
                    break;
                }
                None => break,
            },
        }
    }
    debug!("websocket connection closed");
}

async fn send_message(sink: &mut SplitSink<WebSocket, Message>, message: &FeedMessage) -> bool {
    match serde_json::to_string(message) {
        Ok(json) => match sink.send(Message::text(json)).await {
            Ok(()) => true,
            Err(source) => {
                debug!("websocket write failed: {source}");
                false
            }
        },
        Err(source) => {
            error!("could not serialize a websocket message: {source}");
            false
        }
    }
}
