//! Non-composing attestation property arbiters
//!
//! This module contains arbiters that validate specific properties of attestations
//! in a non-composing manner.

pub mod attester_arbiter_non_composing;
pub mod expiration_time_after_arbiter_non_composing;
pub mod expiration_time_before_arbiter_non_composing;
pub mod expiration_time_equal_arbiter_non_composing;
pub mod recipient_arbiter_non_composing;
pub mod ref_uid_arbiter_non_composing;
pub mod revocable_arbiter_non_composing;
pub mod schema_arbiter_non_composing;
pub mod time_after_arbiter_non_composing;
pub mod time_before_arbiter_non_composing;
pub mod time_equal_arbiter_non_composing;
pub mod uid_arbiter_non_composing;

// Re-export all non-composing arbiters
pub use attester_arbiter_non_composing::*;
pub use expiration_time_after_arbiter_non_composing::*;
pub use expiration_time_before_arbiter_non_composing::*;
pub use expiration_time_equal_arbiter_non_composing::*;
pub use recipient_arbiter_non_composing::*;
pub use ref_uid_arbiter_non_composing::*;
pub use revocable_arbiter_non_composing::*;
pub use schema_arbiter_non_composing::*;
pub use time_after_arbiter_non_composing::*;
pub use time_before_arbiter_non_composing::*;
pub use time_equal_arbiter_non_composing::*;
pub use uid_arbiter_non_composing::*;

/// Convenience struct for accessing non-composing attestation property arbiters
#[derive(Clone)]
pub struct NonComposingArbiters;

impl NonComposingArbiters {
    pub fn attester(&self) -> AttesterArbiterNonComposing {
        AttesterArbiterNonComposing
    }

    pub fn expiration_time_after(&self) -> ExpirationTimeAfterArbiterNonComposing {
        ExpirationTimeAfterArbiterNonComposing
    }

    pub fn expiration_time_before(&self) -> ExpirationTimeBeforeArbiterNonComposing {
        ExpirationTimeBeforeArbiterNonComposing
    }

    pub fn expiration_time_equal(&self) -> ExpirationTimeEqualArbiterNonComposing {
        ExpirationTimeEqualArbiterNonComposing
    }

    pub fn recipient(&self) -> RecipientArbiterNonComposing {
        RecipientArbiterNonComposing
    }

    pub fn ref_uid(&self) -> RefUidArbiterNonComposing {
        RefUidArbiterNonComposing
    }

    pub fn revocable(&self) -> RevocableArbiterNonComposing {
        RevocableArbiterNonComposing
    }

    pub fn schema(&self) -> SchemaArbiterNonComposing {
        SchemaArbiterNonComposing
    }

    pub fn time_after(&self) -> TimeAfterArbiterNonComposing {
        TimeAfterArbiterNonComposing
    }

    pub fn time_before(&self) -> TimeBeforeArbiterNonComposing {
        TimeBeforeArbiterNonComposing
    }

    pub fn time_equal(&self) -> TimeEqualArbiterNonComposing {
        TimeEqualArbiterNonComposing
    }

    pub fn uid(&self) -> UidArbiterNonComposing {
        UidArbiterNonComposing
    }
}
