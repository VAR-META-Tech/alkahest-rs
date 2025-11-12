use crate::{
    clients::arbiters::ArbitersModule, contracts::SpecificAttestationArbiter::DemandData,
    impl_arbiter_api, impl_demand_data_conversions, impl_encode_and_decode,
};

impl_demand_data_conversions!(DemandData);
