use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract ExpirationTimeBeforeArbiterNonComposing {
        struct DemandData {
            uint64 expirationTime;
        }
    }
}

impl_encode_and_decode!(
    ExpirationTimeBeforeArbiterNonComposing,
    encode_expiration_time_before_arbiter_non_composing_demand,
    decode_expiration_time_before_arbiter_non_composing_demand
);
