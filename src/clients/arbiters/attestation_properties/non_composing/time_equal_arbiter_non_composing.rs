use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract TimeEqualArbiterNonComposing {
        struct DemandData {
            uint64 time;
        }
    }
}

impl_encode_and_decode!(
    TimeEqualArbiterNonComposing,
    encode_time_equal_arbiter_non_composing_demand,
    decode_time_equal_arbiter_non_composing_demand
);
