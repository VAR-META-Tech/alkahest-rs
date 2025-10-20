use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract NotArbiter {
        struct DemandData {
            address baseArbiter;
            bytes baseDemand;
        }
    }
}

crate::impl_encode_and_decode!(
    NotArbiter,
    encode_not_arbiter_demand,
    decode_not_arbiter_demand
);

// API implementation
crate::impl_arbiter_api!(
    NotArbiterApi,
    NotArbiter::DemandData,
    encode_not_arbiter_demand,
    decode_not_arbiter_demand
);
