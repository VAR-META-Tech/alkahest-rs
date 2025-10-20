use alloy::sol;

sol! {
    contract RefUidArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            bytes32 refUID;
        }
    }
}

crate::impl_encode_and_decode!(
    RefUidArbiterComposing,
    encode_ref_uid_arbiter_composing_demand,
    decode_ref_uid_arbiter_composing_demand
);