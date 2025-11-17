// Arbiter integration tests module
// This module organizes all arbiter-related tests

pub mod arbiter_all;
pub mod arbiter_any;
pub mod arbiter_not;
pub mod arbiter_recipient;
pub mod arbiter_uid;

// Core arbiter tests split from arbiters_main.rs
pub mod attestation_properties_composing;
pub mod common;
pub mod confirmation_arbiters;
pub mod intrinsics_arbiters;
pub mod specific_attestation_arbiter;
pub mod trivial_arbiter;
pub mod trusted_oracle_arbiter;
pub mod trusted_party_arbiter;
