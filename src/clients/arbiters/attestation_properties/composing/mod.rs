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

// Re-export the contract types and APIs for convenience
pub use attester_arbiter_composing::*;
pub use expiration_time_after_arbiter_composing::*;
pub use expiration_time_before_arbiter_composing::*;
pub use expiration_time_equal_arbiter_composing::*;
pub use recipient_arbiter_composing::*;
pub use ref_uid_arbiter_composing::*;
pub use revocable_arbiter_composing::*;
pub use schema_arbiter_composing::*;
pub use time_after_arbiter_composing::*;
pub use time_before_arbiter_composing::*;
pub use time_equal_arbiter_composing::*;
pub use uid_arbiter_composing::*;

/// Convenience struct for accessing composing attestation property arbiters
#[derive(Clone)]
pub struct ComposingArbiters;

impl ComposingArbiters {
    pub fn attester(&self) -> AttesterArbiterComposing {
        AttesterArbiterComposing
    }

    pub fn expiration_time_after(&self) -> ExpirationTimeAfterArbiterComposing {
        ExpirationTimeAfterArbiterComposing
    }

    pub fn expiration_time_before(&self) -> ExpirationTimeBeforeArbiterComposing {
        ExpirationTimeBeforeArbiterComposing
    }

    pub fn expiration_time_equal(&self) -> ExpirationTimeEqualArbiterComposing {
        ExpirationTimeEqualArbiterComposing
    }

    pub fn recipient(&self) -> RecipientArbiterComposing {
        RecipientArbiterComposing
    }

    pub fn ref_uid(&self) -> RefUidArbiterComposing {
        RefUidArbiterComposing
    }

    pub fn revocable(&self) -> RevocableArbiterComposing {
        RevocableArbiterComposing
    }

    pub fn schema(&self) -> SchemaArbiterComposing {
        SchemaArbiterComposing
    }

    pub fn time_after(&self) -> TimeAfterArbiterComposing {
        TimeAfterArbiterComposing
    }

    pub fn time_before(&self) -> TimeBeforeArbiterComposing {
        TimeBeforeArbiterComposing
    }

    pub fn time_equal(&self) -> TimeEqualArbiterComposing {
        TimeEqualArbiterComposing
    }

    pub fn uid(&self) -> UidArbiterComposing {
        UidArbiterComposing
    }
}
