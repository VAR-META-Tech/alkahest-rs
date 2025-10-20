//! Composing attestation property arbiters
//!
//! This module contains arbiters that validate attestation properties
//! in a composable manner, combining base arbiters with property checks.

pub mod attester_arbiter_composing;
pub mod expiration_time_after_arbiter_composing;
pub mod expiration_time_before_arbiter_composing;
pub mod expiration_time_equal_arbiter_composing;
pub mod recipient_arbiter_composing;
pub mod ref_uid_arbiter_composing;
pub mod revocable_arbiter_composing;
pub mod schema_arbiter_composing;
pub mod time_after_arbiter_composing;
pub mod time_before_arbiter_composing;
pub mod time_equal_arbiter_composing;
pub mod uid_arbiter_composing;

// Re-export the contract types for convenience
pub use attester_arbiter_composing::AttesterArbiterComposing;
pub use expiration_time_after_arbiter_composing::ExpirationTimeAfterArbiterComposing;
pub use expiration_time_before_arbiter_composing::ExpirationTimeBeforeArbiterComposing;
pub use expiration_time_equal_arbiter_composing::ExpirationTimeEqualArbiterComposing;
pub use recipient_arbiter_composing::RecipientArbiterComposing;
pub use ref_uid_arbiter_composing::RefUidArbiterComposing;
pub use revocable_arbiter_composing::RevocableArbiterComposing;
pub use schema_arbiter_composing::SchemaArbiterComposing;
pub use time_after_arbiter_composing::TimeAfterArbiterComposing;
pub use time_before_arbiter_composing::TimeBeforeArbiterComposing;
pub use time_equal_arbiter_composing::TimeEqualArbiterComposing;
pub use uid_arbiter_composing::UidArbiterComposing;
