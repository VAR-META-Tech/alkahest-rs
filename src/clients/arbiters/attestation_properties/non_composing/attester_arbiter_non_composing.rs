use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract AttesterArbiterNonComposing {
        struct DemandData {
            address attester;
        }
    }
}

impl_encode_and_decode!(
    AttesterArbiterNonComposing,
    encode_attester_arbiter_non_composing_demand,
    decode_attester_arbiter_non_composing_demand
);
