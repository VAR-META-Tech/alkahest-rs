use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract AnyArbiter {
        struct DemandData {
            address[] arbiters;
            bytes[] demands;
        }
    }
}

crate::impl_encode_and_decode!(
    AnyArbiter,
    encode_any_arbiter_demand,
    decode_any_arbiter_demand
);

// API implementation
crate::impl_arbiter_api!(
    AnyArbiterApi,
    AnyArbiter::DemandData,
    encode_any_arbiter_demand,
    decode_any_arbiter_demand,
    any_arbiter
);
