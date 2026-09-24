//! What the judge decided.

use serde::Deserialize;

/// The judge's answer for one goal, clause, or program.
///
/// A verdict is a decision about *admission*. It says nothing about what the
/// goal computes, and Hornguard never runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Admissible as written. `canonical` is the operator-free form to hand
    /// the engine; the author's text should not cross.
    Admit { canonical: String },

    /// Admissible as rewritten. Under [`Builder::dynamic_dispatch`] the
    /// judge does not refuse an unbound goal or closure; it rewrites it to a
    /// call the judge sees again at the moment it runs. `canonical` is that
    /// rewritten term, and it is the only thing that may run: the original
    /// was never admitted.
    ///
    /// [`Builder::dynamic_dispatch`]: crate::Builder::dynamic_dispatch
    AdmitWith { canonical: String },

    /// Admissible once the host satisfies each [`Need`]. `canonical` is
    /// already available: the term itself is fine, something around it is
    /// missing.
    AdmitNeeds { needs: Vec<Need>, canonical: String },

    /// Refused. `class` is the threat classification, `rule` names what
    /// decided, `depth` is how deep inside meta-arguments the offending goal
    /// sat (0 at the top level), and `reason` is an ISO error term.
    ///
    /// Showing `reason` to the author is a decision for the host: distinct
    /// messages for "unknown" and "denied" let a prober map the allowlist.
    Refused {
        class: Class,
        rule: String,
        depth: u32,
        reason: String,
    },
}

impl Verdict {
    /// True for [`Verdict::Admit`] and [`Verdict::AdmitWith`], the two
    /// verdicts whose `canonical` may run as it stands. [`Verdict::AdmitNeeds`]
    /// is not yet a yes: the host has something to do first.
    pub fn is_admitted(&self) -> bool {
        matches!(self, Verdict::Admit { .. } | Verdict::AdmitWith { .. })
    }

    pub fn is_refused(&self) -> bool {
        matches!(self, Verdict::Refused { .. })
    }

    /// The operator-free form to hand the engine, when there is one.
    ///
    /// Present for [`Verdict::Admit`] and [`Verdict::AdmitNeeds`]. The
    /// author's variable names are preserved, so bindings the engine reports
    /// can be mapped back to what the author wrote.
    pub fn canonical(&self) -> Option<&str> {
        match self {
            Verdict::Admit { canonical }
            | Verdict::AdmitWith { canonical }
            | Verdict::AdmitNeeds { canonical, .. } => Some(canonical),
            Verdict::Refused { .. } => None,
        }
    }

    /// The needs, empty unless this is [`Verdict::AdmitNeeds`].
    pub fn needs(&self) -> &[Need] {
        match self {
            Verdict::AdmitNeeds { needs, .. } => needs,
            _ => &[],
        }
    }
}

/// Something the host must supply before an otherwise admissible term runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Need {
    /// A profile the judge knows but the host did not put in force.
    Profile(String),
    /// A predicate the engine does not define, reported instead of refused
    /// because the host asked for `defer_unknown`. Usually a rule stored
    /// later, or facts in another namespace.
    Predicate(String),
    /// A need a newer worker reports that this crate does not know.
    Other(serde_json::Value),
}

/// Why a term was refused. Classification is metadata on a decision already
/// made: it never changes the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    /// An unknown predicate, or one allowed only by a profile not in force.
    /// Usually a typo or a missing profile, not an attack.
    BenignMiss,
    /// A pinned predicate called at the top level.
    CapabilityProbe,
    /// A pinned predicate hidden inside a meta-argument, an unbound goal in
    /// call position, or module qualification. The author expected the outer
    /// goal to pass.
    EscapeAttempt,
    /// Reflection, at any depth.
    Reconnaissance,
    /// A clause whose head would stand in for a definition the judge reasons
    /// about: a trusted, allowed, pinned or control predicate, a qualified or
    /// unbound head. The body is walked regardless; the harm is to what the
    /// host's predicate answers. Read it by recurrence: one is worth a look,
    /// the same head across many scopes is a policy gap.
    Shadowing,
    /// Admissible capability-wise, but with no single intended meaning:
    /// recursion through negation or aggregation, or negation used as if it
    /// bound a variable. Not a threat signal.
    Semantics,
    /// A hostile term shape: cyclic, pathologically deep, or text the reader
    /// refused.
    Evasion,
    /// A class a newer worker reports that this crate does not know.
    Other(String),
}

impl Class {
    /// True for the classes that indicate someone testing the boundary:
    /// [`Class::CapabilityProbe`], [`Class::EscapeAttempt`],
    /// [`Class::Reconnaissance`], [`Class::Shadowing`] and [`Class::Evasion`].
    ///
    /// [`Class::BenignMiss`] and [`Class::Semantics`] are ordinary author
    /// mistakes. An unknown class is treated as adversarial: a newer worker
    /// would not add a class for something harmless.
    pub fn is_adversarial(&self) -> bool {
        !matches!(self, Class::BenignMiss | Class::Semantics)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Class::BenignMiss => "benign_miss",
            Class::CapabilityProbe => "capability_probe",
            Class::EscapeAttempt => "escape_attempt",
            Class::Reconnaissance => "reconnaissance",
            Class::Shadowing => "shadowing",
            Class::Semantics => "semantics",
            Class::Evasion => "evasion",
            Class::Other(s) => s,
        }
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Class {
    fn from(s: &str) -> Self {
        match s {
            "benign_miss" => Class::BenignMiss,
            "capability_probe" => Class::CapabilityProbe,
            "escape_attempt" => Class::EscapeAttempt,
            "reconnaissance" => Class::Reconnaissance,
            "shadowing" => Class::Shadowing,
            "semantics" => Class::Semantics,
            "evasion" => Class::Evasion,
            other => Class::Other(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------- wire types

#[derive(Debug, Deserialize)]
pub(crate) struct Response {
    pub(crate) id: Option<u64>,
    #[serde(default)]
    pub(crate) verdict: Option<String>,
    #[serde(default)]
    pub(crate) canonical: Option<String>,
    #[serde(default)]
    pub(crate) needs: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub(crate) class: Option<String>,
    #[serde(default)]
    pub(crate) rule: Option<String>,
    #[serde(default)]
    pub(crate) depth: Option<u32>,
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) ok: Option<bool>,
    #[serde(default)]
    pub(crate) profiles: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) error: Option<String>,
    #[serde(default)]
    pub(crate) detail: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Hello {
    pub(crate) hello: String,
    pub(crate) protocol: u32,
    #[serde(default)]
    pub(crate) engine: Option<String>,
    #[serde(default)]
    pub(crate) version: Option<String>,
    #[serde(default)]
    pub(crate) profiles: Vec<String>,
}

pub(crate) fn need_from_json(v: serde_json::Value) -> Need {
    if let Some(p) = v.get("profile").and_then(|p| p.as_str()) {
        Need::Profile(p.to_string())
    } else if let Some(p) = v.get("predicate").and_then(|p| p.as_str()) {
        Need::Predicate(p.to_string())
    } else {
        Need::Other(v)
    }
}
