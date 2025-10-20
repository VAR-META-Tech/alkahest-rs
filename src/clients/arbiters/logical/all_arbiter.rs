use crate::clients::arbiters::ArbitersModule;
use alloy::sol;

sol! {
    contract AllArbiter {
        struct DemandData {
            address[] arbiters;
            bytes[] demands;
        }
    }
}

crate::impl_encode_and_decode!(
    AllArbiter,
    encode_all_arbiter_demand,
    decode_all_arbiter_demand
);

// API implementation
crate::impl_arbiter_api!(
    AllArbiterApi,
    AllArbiter::DemandData,
    encode_all_arbiter_demand,
    decode_all_arbiter_demand
);
