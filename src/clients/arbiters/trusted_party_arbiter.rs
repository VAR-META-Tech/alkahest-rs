use crate::{
    clients::arbiters::ArbitersModule, contracts::TrustedPartyArbiter::DemandData,
    impl_arbiter_api, impl_encode_and_decode, impl_demand_data_conversions,
};

impl_demand_data_conversions!(DemandData);


