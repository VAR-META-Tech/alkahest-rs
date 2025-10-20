use alloy::sol;

sol! {
    contract RevocableConfirmationArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
        }
    }
}

crate::impl_encode_and_decode!(
    RevocableConfirmationArbiterComposing,
    encode_revocable_confirmation_arbiter_composing_demand,
    decode_revocable_confirmation_arbiter_composing_demand
);
