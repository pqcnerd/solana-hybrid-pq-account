//! Cryptographic authorization modules.
//!
//! Implementations land in Milestones 2–5. These modules exist so the
//! dependency graph and call sites are planned; they MUST NOT return a
//! permissive success until real verification is wired.

pub mod ed25519;
pub mod falcon;
pub mod policy;
