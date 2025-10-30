//! Confirmation arbiters module
//!
//! This module contains arbiters that handle confirmation-based logic
//! for attestation validation and composition.

pub mod confirmation_arbiter_composing;
pub mod revocable_confirmation_arbiter_composing;
pub mod unrevocable_confirmation_arbiter_composing;

// Re-export the contract types and APIs for convenience
pub use confirmation_arbiter_composing::*;
pub use revocable_confirmation_arbiter_composing::*;
pub use unrevocable_confirmation_arbiter_composing::*;

// Confirmation arbiters group
#[derive(Clone)]
pub struct ConfirmationArbiters;

impl ConfirmationArbiters {
    pub fn confirmation_composing(&self) -> ConfirmationArbiterComposing {
        ConfirmationArbiterComposing
    }

    pub fn revocable_confirmation_composing(&self) -> RevocableConfirmationArbiterComposing {
        RevocableConfirmationArbiterComposing
    }

    pub fn unrevocable_confirmation_composing(&self) -> UnrevocableConfirmationArbiterComposing {
        UnrevocableConfirmationArbiterComposing
    }
}
