use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::AttesterArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

