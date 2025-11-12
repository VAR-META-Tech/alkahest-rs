use crate::{clients::arbiters::ArbitersModule, 
    contracts::attestation_properties::non_composing::TimeBeforeArbiter::DemandData,
    impl_encode_and_decode, impl_demand_data_conversions, impl_arbiter_api
};

impl_demand_data_conversions!(DemandData);

