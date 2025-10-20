use alloy::sol;

sol! {
    contract TimeBeforeArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            uint64 time;
        }
    }
}

crate::impl_encode_and_decode!(
    TimeBeforeArbiterComposing,
    encode_time_before_arbiter_composing_demand,
    decode_time_before_arbiter_composing_demand
);