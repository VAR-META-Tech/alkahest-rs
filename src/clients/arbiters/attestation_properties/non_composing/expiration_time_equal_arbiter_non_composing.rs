use crate::impl_encode_and_decode;
use alloy::sol;

sol! {
    contract ExpirationTimeEqualArbiterNonComposing {
        struct DemandData {
            uint64 expirationTime;
        }
    }
}

impl_encode_and_decode!(
    ExpirationTimeEqualArbiterNonComposing,
    encode_expiration_time_equal_arbiter_non_composing_demand,
    decode_expiration_time_equal_arbiter_non_composing_demand
);
