//! Things that can go wrong reaching the judge.
//!
//! None of these is a verdict. A refusal is a [`crate::Verdict::Refused`],
//! which is a successful judgment; the errors here mean the judge could not
//! be reached or did not answer.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// The worker could not be started. Usually `swipl` is not on `PATH` or
    /// the pack is not where the crate looked.
    Spawn {
        path: String,
        source: std::io::Error,
    },

    /// The pack could not be located. Set `HORNGUARD_HOME` to the checkout,
    /// or pass a path to [`crate::Hornguard::builder`].
    PackNotFound {
        tried: Vec<String>,
    },

    /// The worker greeted us with a protocol version this crate does not
    /// speak. Upgrade whichever side is older; the protocol version is in the
    /// handshake for exactly this reason.
    Protocol {
        expected: u32,
        got: u32,
    },

    /// The worker sent something that was not a greeting on startup.
    Handshake(String),

    /// The worker exited, or closed its pipes, while we were talking to it.
    /// The judge process is gone; build a new [`crate::Hornguard`].
    WorkerGone,

    /// A response arrived for a request we did not send, or out of order.
    /// The worker is sequential, so this means the stream is desynchronised
    /// and the connection can no longer be trusted.
    Desync {
        expected: u64,
        got: Option<u64>,
    },

    /// The worker rejected the request itself: an unknown op, a malformed
    /// request, a policy file that would not load.
    Worker {
        kind: String,
        detail: String,
    },

    /// The worker answered, but not in a shape this crate understands.
    Malformed(String),

    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Spawn { path, source } => {
                write!(f, "could not start the judge worker ({path}): {source}")
            }
            Error::PackNotFound { tried } => write!(
                f,
                "could not find the hornguard pack; set HORNGUARD_HOME or pass a path (tried: {})",
                tried.join(", ")
            ),
            Error::Protocol { expected, got } => write!(
                f,
                "judge worker speaks protocol {got}, this crate speaks {expected}"
            ),
            Error::Handshake(s) => write!(f, "judge worker did not greet us: {s}"),
            Error::WorkerGone => f.write_str("the judge worker exited"),
            Error::Desync { expected, got } => match got {
                Some(g) => write!(f, "response id {g} for request {expected}"),
                None => write!(f, "response with no id for request {expected}"),
            },
            Error::Worker { kind, detail } => {
                write!(f, "judge worker refused the request ({kind}): {detail}")
            }
            Error::Malformed(s) => write!(f, "could not read the judge worker's answer: {s}"),
            Error::Io(e) => write!(f, "{e}"),
            Error::Json(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Spawn { source, .. } => Some(source),
            Error::Io(e) => Some(e),
            Error::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
