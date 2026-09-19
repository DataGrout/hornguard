//! A default-deny firewall for untrusted Prolog.
//!
//! Hornguard judges a goal, clause, or clause set before a Prolog engine runs
//! it: admitted, admitted subject to something the host must supply, or
//! refused with a reason and a classification. The default is deny, every
//! rule is an allow rule, and a set of capability classes is pinned shut that
//! no profile can reopen.
//!
//! This crate is a client. The judgment happens in a separate SWI-Prolog
//! process, the *judge worker*, so the judge runs where an author's code
//! cannot reach it. The crate spawns that process, speaks its line protocol,
//! and gives you a [`Verdict`].
//!
//! ```no_run
//! use hornguard::{Hornguard, Verdict};
//!
//! let mut hg = Hornguard::builder()
//!     .profiles(["iso", "prologue"])
//!     .spawn()?;
//!
//! match hg.judge_goal("findall(X, member(X, [a, b]), L)")? {
//!     Verdict::Admit { canonical } => {
//!         // Hand `canonical` to the engine, never the author's text.
//!         println!("ok: {canonical}");
//!     }
//!     Verdict::AdmitNeeds { needs, .. } => println!("needs {needs:?}"),
//!     Verdict::Refused { class, rule, .. } => println!("refused: {class} ({rule})"),
//! }
//! # Ok::<(), hornguard::Error>(())
//! ```
//!
//! # What this crate does not do
//!
//! It judges. It never executes Prolog, and it deliberately offers no way to.
//! Running an admitted goal is the host's job, under the host's engine, with
//! the host's caps and isolation. Hornguard's judgment is one layer of a safe
//! Prolog host, and the cheapest; see the repository's architecture notes for
//! the rest.
//!
//! # Requirements
//!
//! SWI-Prolog 9.2 or later on `PATH`, and the Hornguard pack. The crate finds
//! the pack by, in order: the path given to [`Builder::home`], the
//! `HORNGUARD_HOME` environment variable, and then asking `swipl` where the
//! installed pack lives.
//!
//! # Concurrency
//!
//! A worker is sequential, so judging takes `&mut self`. A host wanting
//! parallelism spawns several [`Hornguard`] values; they share nothing.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod error;
mod verdict;

pub use error::{Error, Result};
pub use verdict::{Class, Need, Verdict};

use serde_json::{json, Value};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// The protocol version this crate speaks. The worker announces its own in
/// the handshake and a mismatch is [`Error::Protocol`] rather than a
/// confusing failure later.
pub const PROTOCOL_VERSION: u32 = 1;

/// A running judge worker.
///
/// Dropping this kills the worker process.
#[derive(Debug)]
pub struct Hornguard {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    engine: Option<String>,
    engine_version: Option<String>,
    profiles_at_start: Vec<String>,
    defaults: Defaults,
}

#[derive(Debug, Clone, Default)]
struct Defaults {
    backend: Option<String>,
    profiles: Option<Vec<String>>,
    strict_negation: Option<bool>,
    defer_unknown: Option<bool>,
    allow: Option<Vec<String>>,
    trust: Option<Vec<(String, String)>>,
}

impl Hornguard {
    /// Start configuring a worker.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// The engine the worker runs on, as it reported at startup.
    pub fn engine(&self) -> Option<&str> {
        self.engine.as_deref()
    }

    /// The engine's version, as it reported at startup.
    pub fn engine_version(&self) -> Option<&str> {
        self.engine_version.as_deref()
    }

    /// The profiles the worker knew at startup. Use [`Hornguard::profiles`]
    /// for the current list after loading more.
    pub fn profiles_at_start(&self) -> &[String] {
        &self.profiles_at_start
    }

    /// Judge one goal.
    ///
    /// The text is the author's, unparsed. The worker reads it under the
    /// backend's reader flags, so the engine never has to parse author text:
    /// hand it [`Verdict::canonical`] instead.
    pub fn judge_goal(&mut self, text: &str) -> Result<Verdict> {
        self.judge("judge_goal", text)
    }

    /// Judge one clause for storage. The body is judged exactly as a goal;
    /// the head may not shadow a pinned predicate, a profile predicate, or a
    /// control construct.
    pub fn judge_clause(&mut self, text: &str) -> Result<Verdict> {
        self.judge("judge_clause", text)
    }

    /// Judge a clause set as one program: the set's own heads are admitted in
    /// each other's bodies, and the whole must be stratified.
    pub fn judge_program(&mut self, text: &str) -> Result<Verdict> {
        self.judge("judge_program", text)
    }

    /// Load a host policy file: backend, profiles, options, host `allow` and
    /// `trust` declarations. A failed load leaves the previous policy in force.
    pub fn load_policy(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let req = json!({ "op": "load_policy", "path": path_string(path.as_ref()) });
        self.request(req).and_then(expect_ok)
    }

    /// Replace the loaded profiles with those under the given directories, in
    /// order. A host installs its own profiles by listing its directory after
    /// the pack's.
    pub fn load_profiles<I, P>(&mut self, dirs: I) -> Result<()>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let dirs: Vec<String> = dirs.into_iter().map(|d| path_string(d.as_ref())).collect();
        self.request(json!({ "op": "load_profiles", "dirs": dirs }))
            .and_then(expect_ok)
    }

    /// The profile names the worker currently knows.
    pub fn profiles(&mut self) -> Result<Vec<String>> {
        let resp = self.request(json!({ "op": "profiles" }))?;
        resp.profiles
            .ok_or_else(|| Error::Malformed("profiles response had no profiles".into()))
    }

    /// Check the worker is alive and answering.
    pub fn ping(&mut self) -> Result<()> {
        self.request(json!({ "op": "ping" })).and_then(expect_ok)
    }

    // ------------------------------------------------------------ internals

    fn judge(&mut self, op: &str, text: &str) -> Result<Verdict> {
        let mut req = serde_json::Map::new();
        req.insert("op".into(), json!(op));
        req.insert("text".into(), json!(text));
        if let Some(b) = &self.defaults.backend {
            req.insert("backend".into(), json!(b));
        }
        if let Some(p) = &self.defaults.profiles {
            req.insert("profiles".into(), json!(p));
        }
        let mut opts = serde_json::Map::new();
        if let Some(v) = self.defaults.strict_negation {
            opts.insert("strict_negation".into(), json!(v));
        }
        if let Some(v) = self.defaults.defer_unknown {
            opts.insert("defer_unknown".into(), json!(v));
        }
        if let Some(a) = &self.defaults.allow {
            opts.insert("allow".into(), json!(a));
        }
        if let Some(t) = &self.defaults.trust {
            let pairs: Vec<Vec<&str>> = t
                .iter()
                .map(|(ind, spec)| vec![ind.as_str(), spec.as_str()])
                .collect();
            opts.insert("trust".into(), json!(pairs));
        }
        if !opts.is_empty() {
            req.insert("options".into(), Value::Object(opts));
        }

        let resp = self.request(Value::Object(req))?;
        verdict_from(resp)
    }

    fn request(&mut self, mut req: Value) -> Result<verdict::Response> {
        let id = self.next_id;
        self.next_id += 1;
        if let Some(obj) = req.as_object_mut() {
            obj.insert("id".into(), json!(id));
        }

        let line = serde_json::to_string(&req)?;
        writeln!(self.stdin, "{line}").map_err(broken_pipe)?;
        self.stdin.flush().map_err(broken_pipe)?;

        let resp: verdict::Response = self.read_response()?;

        if resp.id != Some(id) {
            return Err(Error::Desync {
                expected: id,
                got: resp.id,
            });
        }
        if let Some(kind) = &resp.error {
            return Err(Error::Worker {
                kind: kind.clone(),
                detail: resp.detail.clone().unwrap_or_default(),
            });
        }
        Ok(resp)
    }

    fn read_response(&mut self) -> Result<verdict::Response> {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line)?;
        if n == 0 {
            return Err(Error::WorkerGone);
        }
        serde_json::from_str(&line).map_err(|e| Error::Malformed(format!("{e}: {}", line.trim())))
    }
}

impl Drop for Hornguard {
    fn drop(&mut self) {
        // Closing stdin ends the worker's loop; kill covers a wedged one.
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An op that reports success rather than a verdict must actually say so.
fn expect_ok(resp: verdict::Response) -> Result<()> {
    match resp.ok {
        Some(true) => Ok(()),
        _ => Err(Error::Malformed("expected {\"ok\":true}".into())),
    }
}

fn broken_pipe(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        Error::WorkerGone
    } else {
        Error::Io(e)
    }
}

fn verdict_from(resp: verdict::Response) -> Result<Verdict> {
    let verdict = resp
        .verdict
        .as_deref()
        .ok_or_else(|| Error::Malformed("response had no verdict".into()))?;
    match verdict {
        "admit" => Ok(Verdict::Admit {
            canonical: resp.canonical.unwrap_or_default(),
        }),
        "admit_needs" => Ok(Verdict::AdmitNeeds {
            needs: resp
                .needs
                .unwrap_or_default()
                .into_iter()
                .map(verdict::need_from_json)
                .collect(),
            canonical: resp.canonical.unwrap_or_default(),
        }),
        "refused" => Ok(Verdict::Refused {
            class: resp.class.as_deref().unwrap_or("").into(),
            rule: resp.rule.unwrap_or_default(),
            depth: resp.depth.unwrap_or(0),
            reason: resp.reason.unwrap_or_default(),
        }),
        other => Err(Error::Malformed(format!("unknown verdict {other:?}"))),
    }
}

fn path_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Configuration for a judge worker.
///
/// Everything here is optional. With no configuration the crate finds the
/// pack, starts a worker, and judges under whatever policy the worker loads
/// by default.
#[derive(Debug, Default, Clone)]
pub struct Builder {
    swipl: Option<OsString>,
    home: Option<PathBuf>,
    policy: Option<PathBuf>,
    profile_dirs: Option<Vec<PathBuf>>,
    defaults: Defaults,
}

impl Builder {
    /// The `swipl` executable. Defaults to `swipl` on `PATH`.
    pub fn swipl(mut self, path: impl Into<OsString>) -> Self {
        self.swipl = Some(path.into());
        self
    }

    /// The Hornguard checkout or pack directory, the one containing
    /// `prolog/hornguard_worker_main.pl`.
    pub fn home(mut self, path: impl Into<PathBuf>) -> Self {
        self.home = Some(path.into());
        self
    }

    /// A policy file to load once the worker starts.
    pub fn policy(mut self, path: impl Into<PathBuf>) -> Self {
        self.policy = Some(path.into());
        self
    }

    /// Profile directories to load once the worker starts, in order. List the
    /// pack's own directory first if you want the shipped profiles too.
    pub fn profile_dirs<I, P>(mut self, dirs: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.profile_dirs = Some(dirs.into_iter().map(Into::into).collect());
        self
    }

    /// The backend to judge against: `iso`, `swi`, and later others. `iso` is
    /// judge-only and knows nothing about any engine; `swi` also asks the
    /// engine, so an allowed predicate the engine declares meta but no profile
    /// gives a spec for is refused.
    pub fn backend(mut self, backend: impl Into<String>) -> Self {
        self.defaults.backend = Some(backend.into());
        self
    }

    /// The profiles in force for every judgment.
    pub fn profiles<I, S>(mut self, profiles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.defaults.profiles = Some(profiles.into_iter().map(Into::into).collect());
        self
    }

    /// Refuse a negated goal that introduces a variable used after it.
    /// Defaults to on in the worker: negation never binds, so such a variable
    /// is unbound where it is used.
    pub fn strict_negation(mut self, on: bool) -> Self {
        self.defaults.strict_negation = Some(on);
        self
    }

    /// Report a predicate the engine does not define as a [`Need::Predicate`]
    /// instead of refusing it, so a rule may be stored before the rules it
    /// calls. Never widens the engine surface.
    pub fn defer_unknown(mut self, on: bool) -> Self {
        self.defaults.defer_unknown = Some(on);
        self
    }

    /// Host predicates whose clauses live in sandboxed space and were
    /// body-judged when stored, as `"name/arity"`.
    pub fn allow<I, S>(mut self, indicators: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.defaults.allow = Some(indicators.into_iter().map(Into::into).collect());
        self
    }

    /// Host predicates admitted without walking their bodies, as
    /// `("name/arity", spec)` where spec is `"none"` or a meta-predicate
    /// term such as `"with_tenant(?,0)"`.
    ///
    /// This is the one real escape hatch: a trusted predicate's body is never
    /// judged. Declare a spec for anything that takes a goal.
    pub fn trust<I, A, B>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = (A, B)>,
        A: Into<String>,
        B: Into<String>,
    {
        self.defaults.trust = Some(
            entries
                .into_iter()
                .map(|(a, b)| (a.into(), b.into()))
                .collect(),
        );
        self
    }

    /// Start the worker.
    pub fn spawn(self) -> Result<Hornguard> {
        let swipl = self.swipl.clone().unwrap_or_else(|| "swipl".into());
        let script = locate_worker(self.home.as_deref(), &swipl)?;

        let mut child = Command::new(&swipl)
            .arg("-q")
            .arg(&script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| Error::Spawn {
                path: script.to_string_lossy().into_owned(),
                source,
            })?;

        let stdin = child.stdin.take().ok_or(Error::WorkerGone)?;
        let stdout = BufReader::new(child.stdout.take().ok_or(Error::WorkerGone)?);

        let mut hg = Hornguard {
            child,
            stdin,
            stdout,
            next_id: 1,
            engine: None,
            engine_version: None,
            profiles_at_start: Vec::new(),
            defaults: self.defaults,
        };

        let mut line = String::new();
        let n = hg.stdout.read_line(&mut line)?;
        if n == 0 {
            return Err(Error::WorkerGone);
        }
        let hello: verdict::Hello =
            serde_json::from_str(&line).map_err(|_| Error::Handshake(line.trim().to_string()))?;
        if hello.hello != "hornguard" {
            return Err(Error::Handshake(line.trim().to_string()));
        }
        if hello.protocol != PROTOCOL_VERSION {
            return Err(Error::Protocol {
                expected: PROTOCOL_VERSION,
                got: hello.protocol,
            });
        }
        hg.engine = hello.engine;
        hg.engine_version = hello.version;
        hg.profiles_at_start = hello.profiles;

        if let Some(dirs) = &self.profile_dirs {
            hg.load_profiles(dirs)?;
        }
        if let Some(policy) = &self.policy {
            hg.load_policy(policy)?;
        }
        Ok(hg)
    }
}

/// Find `prolog/hornguard_worker_main.pl`: explicit path, then
/// `HORNGUARD_HOME`, then whatever `swipl` says about the installed pack.
fn locate_worker(home: Option<&Path>, swipl: &OsString) -> Result<PathBuf> {
    let mut tried = Vec::new();

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(h) = home {
        candidates.push(h.to_path_buf());
    }
    if let Some(env) = std::env::var_os("HORNGUARD_HOME") {
        candidates.push(PathBuf::from(env));
    }

    for base in candidates {
        let direct = base.join("prolog").join("hornguard_worker_main.pl");
        if direct.is_file() {
            return Ok(direct);
        }
        tried.push(direct.to_string_lossy().into_owned());
        // A path pointing straight at the script is a reasonable thing to pass.
        if base.is_file() {
            return Ok(base);
        }
    }

    if let Some(dir) = pack_directory(swipl) {
        let p = dir.join("prolog").join("hornguard_worker_main.pl");
        if p.is_file() {
            return Ok(p);
        }
        tried.push(p.to_string_lossy().into_owned());
    } else {
        tried.push("swipl pack_property(hornguard, directory(_))".into());
    }

    Err(Error::PackNotFound { tried })
}

fn pack_directory(swipl: &OsString) -> Option<PathBuf> {
    let out = Command::new(swipl)
        .arg("-q")
        .arg("-g")
        .arg("catch((pack_property(hornguard, directory(D)), write(D)), _, true)")
        .arg("-t")
        .arg("halt")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}
