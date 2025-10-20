use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract UidArbiterComposing {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
            bytes32 uid;
        }
    }
}

crate::impl_encode_and_decode!(
    UidArbiterComposing,
    encode_uid_arbiter_composing_demand,
    decode_uid_arbiter_composing_demand
);

crate::impl_arbiter_api!(
    UidArbiterComposingApi,
    UidArbiterComposing::DemandData,
    encode_uid_arbiter_composing_demand,
    decode_uid_arbiter_composing_demand
);
