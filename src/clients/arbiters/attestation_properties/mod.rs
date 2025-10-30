//! Attestation properties arbiters module
//!
//! This module contains arbiters that validate specific properties of attestations,
//! such as time constraints, recipients, schemas, and other metadata.

pub mod composing;
pub mod non_composing;

// Re-export modules for convenience
pub use composing::*;
pub use non_composing::*;

/// Convenience struct for accessing attestation property arbiters
#[derive(Clone)]
pub struct AttestationPropertyArbiters;

impl AttestationPropertyArbiters {
    pub fn composing(&self) -> ComposingArbiters {
        ComposingArbiters
    }

    pub fn non_composing(&self) -> NonComposingArbiters {
        NonComposingArbiters
    }
}
