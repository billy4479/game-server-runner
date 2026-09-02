//! Serving the Svelte frontend. With the `embed-frontend` feature the
//! built assets from `frontend/dist` are embedded into the binary;
//! without it, non-API requests get a placeholder page pointing at the
//! build commands.

use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

#[cfg(not(feature = "embed-frontend"))]
use axum::response::Html;

/// Everything under `/api` belongs to the API, never to the frontend.
fn is_api(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// Fallback for everything the API routes do not claim: GET and HEAD on
/// non-API paths serve the frontend, anything else is a 404.
pub async fn fallback(method: Method, uri: Uri) -> Response {
    if is_api(uri.path()) || (method != Method::GET && method != Method::HEAD) {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve(uri.path())
}

/// The placeholder shown when the binary was built without the frontend.
#[cfg(not(feature = "embed-frontend"))]
fn serve(_path: &str) -> Response {
    Html(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>game-server-runner</title></head><body>\
         <h1>Frontend not built</h1>\
         <p>Run <code>pnpm build</code> in <code>frontend/</code>, then rebuild \
         this binary with <code>--features embed-frontend</code>.</p>\
         </body></html>",
    )
    .into_response()
}

/// The built Svelte app, embedded at compile time. `frontend/dist` must
/// exist when cargo runs; produce it with `pnpm build` in `frontend/`.
#[cfg(feature = "embed-frontend")]
use axum::http::header;

#[cfg(feature = "embed-frontend")]
#[derive(rust_embed::RustEmbed)]
#[folder = "frontend/dist"]
struct Assets;

/// Serve an embedded asset, with the SPA fallback to `index.html` for
/// extensionless paths.
#[cfg(feature = "embed-frontend")]
fn serve(path: &str) -> Response {
    let trimmed = path.trim_start_matches('/');
    let requested = if trimmed.is_empty() {
        "index.html"
    } else {
        trimmed
    };

    let (served, asset) = match Assets::get(requested) {
        Some(asset) => (requested, asset),
        // Extensionless paths, like /login, are client-side routes.
        None if requested.contains('.') => return StatusCode::NOT_FOUND.into_response(),
        None => match Assets::get("index.html") {
            Some(asset) => ("index.html", asset),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };

    let mime = mime_guess::from_path(served).first_or_octet_stream();
    ([(header::CONTENT_TYPE, mime.as_ref())], asset.data).into_response()
}
