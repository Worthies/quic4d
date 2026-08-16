//! Process-lifetime Tokio runtime shared by every endpoint-creation entry
//! point (see api/bridge.rs and core/endpoint.rs).
//!
//! quinn::Endpoint::client()/server() spawn the endpoint's I/O driver task
//! onto whatever Tokio runtime is "current" at construction time (via
//! quinn's `default_runtime()` -> `Handle::try_current()`). Every endpoint-
//! creation call used to build its own throwaway `tokio::runtime::Runtime`
//! with `Runtime::new()`, run the constructor inside `rt.block_on(...)`,
//! and then drop `rt` the moment the function returned. Dropping a Tokio
//! `Runtime` immediately cancels every task spawned on it — including the
//! driver task just spawned by quinn — which sets the endpoint's internal
//! `driver_lost` flag. The endpoint object survives (it's just a handle),
//! but the very next `connect()` call on it fails fast with
//! `ConnectError::EndpointStopping` ("Failed to initiate connection:
//! EndpointStopping") because Quinn refuses to start a connection once its
//! driver is gone.
//!
//! The fix is to spawn the driver onto a runtime that outlives the
//! constructor call — this one, initialized lazily and kept alive for the
//! whole process via `OnceLock`.
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static SHARED_RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// The shared runtime every endpoint-creation entry point must run its
/// constructor on, so the quinn driver task it spawns stays alive for as
/// long as the endpoint itself does.
pub fn shared_runtime() -> &'static Runtime {
    SHARED_RUNTIME.get_or_init(|| {
        Runtime::new().expect("Failed to create shared flutter_quic runtime")
    })
}
