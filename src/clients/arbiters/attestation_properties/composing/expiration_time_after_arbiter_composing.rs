use alloy::sol;

sol! {
    contract ExpirationTimeAfterArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 expirationTime;
        }
    }
}

crate::impl_encode_and_decode!(
    ExpirationTimeAfterArbiterComposing,
    encode_expiration_time_after_arbiter_composing_demand,
    decode_expiration_time_after_arbiter_composing_demand
);