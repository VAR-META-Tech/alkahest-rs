use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract TimeAfterArbiterNonComposing {
        struct DemandData {
            uint64 time;
        }
    }
}

impl_encode_and_decode!(
    TimeAfterArbiterNonComposing,
    encode_time_after_arbiter_non_composing_demand,
    decode_time_after_arbiter_non_composing_demand
);
