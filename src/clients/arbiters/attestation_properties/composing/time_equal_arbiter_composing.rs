use crate::clients::arbiters::DecodedDemand;
use crate::{
    clients::arbiters::ArbitersModule,
    contracts::attestation_properties::composing::TimeEqualArbiter::DemandData, impl_arbiter_api,
    impl_demand_data_conversions, impl_encode_and_decode,
};
use alloy::primitives::Address;

impl_demand_data_conversions!(DemandData);

/// Decoded version of TimeEqualArbiter::DemandData with actual demand structure instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedTimeEqualArbiterComposingDemandData {
    /// Same base arbiter address as original
    pub base_arbiter: Address,
    /// Decoded base demand instead of raw bytes
    pub base_demand: DecodedDemand,
    /// Same time uint64 as original
    pub time: u64,
}

impl ArbitersModule {
    pub fn decode_time_equal_arbiter_composing_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedTimeEqualArbiterComposingDemandData> {
        let base_arbiter = demand_data.baseArbiter;
        let time = demand_data.time;
        let decoded_base_demand =
            self.decode_arbiter_demand(demand_data.baseArbiter, &demand_data.baseDemand)?;

        Ok(DecodedTimeEqualArbiterComposingDemandData {
            base_arbiter,
            base_demand: decoded_base_demand,
            time,
        })
    }
}
