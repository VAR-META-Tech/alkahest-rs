//! Logical arbiters module
//!
//! This module contains logical arbiters that combine multiple arbiters
//! using logical operations (ANY, ALL, NOT).
//!
//! These arbiters use trait-based encoding/decoding for convenient .into() conversions.

pub mod all_arbiter;
pub mod any_arbiter;
pub mod not_arbiter;
pub use all_arbiter::AllArbiter;
pub use any_arbiter::AnyArbiter;
pub use not_arbiter::NotArbiter;

// Logical arbiters group
#[derive(Clone)]
pub struct LogicalArbiters;

impl LogicalArbiters {
    pub fn any(&self) -> AnyArbiter {
        AnyArbiter
    }
    pub fn all(&self) -> AllArbiter {
        AllArbiter
    }
    pub fn not(&self) -> NotArbiter {
        NotArbiter
    }
}
