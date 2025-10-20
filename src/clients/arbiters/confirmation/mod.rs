//! Confirmation arbiters module
//!
//! This module contains arbiters that handle confirmation-based logic
//! for attestation validation and composition.

pub mod confirmation_arbiter_composing;
pub mod revocable_confirmation_arbiter_composing;
pub mod unrevocable_confirmation_arbiter_composing;

// Re-export the contract types for convenience
pub use confirmation_arbiter_composing::ConfirmationArbiterComposing;
pub use revocable_confirmation_arbiter_composing::RevocableConfirmationArbiterComposing;
pub use unrevocable_confirmation_arbiter_composing::UnrevocableConfirmationArbiterComposing;
