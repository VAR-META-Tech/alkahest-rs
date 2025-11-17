use crate::clients::arbiters::DecodedDemand;
use crate::{
    clients::arbiters::ArbitersModule,
    contracts::attestation_properties::composing::TimeBeforeArbiter::DemandData,
    impl_demand_data_conversions,
};
use alloy::primitives::Address;

impl_demand_data_conversions!(DemandData);

/// Decoded version of TimeBeforeArbiter::DemandData with actual demand structure instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedTimeBeforeArbiterComposingDemandData {
    /// Same base arbiter address as original
    pub base_arbiter: Address,
    /// Decoded base demand instead of raw bytes
    pub base_demand: Box<DecodedDemand>,
    /// Same time uint64 as original
    pub time: u64,
}

impl ArbitersModule {
    pub fn decode_time_before_arbiter_composing_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedTimeBeforeArbiterComposingDemandData> {
        let base_arbiter = demand_data.baseArbiter;
        let time = demand_data.time;
        let decoded_base_demand =
            self.decode_arbiter_demand(demand_data.baseArbiter, &demand_data.baseDemand)?;

        Ok(DecodedTimeBeforeArbiterComposingDemandData {
            base_arbiter,
            base_demand: Box::new(decoded_base_demand),
            time,
        })
    }
}
