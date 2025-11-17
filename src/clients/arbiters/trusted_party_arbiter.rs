use crate::{
    clients::arbiters::ArbitersModule, contracts::TrustedPartyArbiter::DemandData,
    impl_demand_data_conversions,
};

impl_demand_data_conversions!(DemandData);
