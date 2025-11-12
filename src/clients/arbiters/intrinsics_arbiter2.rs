use crate::{
    clients::arbiters::ArbitersModule, contracts::IntrinsicsArbiter2::DemandData, impl_arbiter_api,
    impl_demand_data_conversions, impl_encode_and_decode,
};

impl_demand_data_conversions!(DemandData);
