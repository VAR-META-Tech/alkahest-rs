use crate::clients::arbiters::DecodedDemand;
use crate::{
    clients::arbiters::ArbitersModule,
    contracts::attestation_properties::composing::RevocableArbiter::DemandData, impl_arbiter_api,
    impl_demand_data_conversions, impl_encode_and_decode,
};
use alloy::primitives::Address;

impl_demand_data_conversions!(DemandData);

/// Decoded version of RevocableArbiter::DemandData with actual demand structure instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedRevocableArbiterComposingDemandData {
    /// Same base arbiter address as original
    pub base_arbiter: Address,
    /// Decoded base demand instead of raw bytes
    pub base_demand: Box<DecodedDemand>,
    /// Same revocable bool as original
    pub revocable: bool,
}

impl ArbitersModule {
    pub fn decode_revocable_arbiter_composing_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedRevocableArbiterComposingDemandData> {
        let base_arbiter = demand_data.baseArbiter;
        let revocable = demand_data.revocable;
        let decoded_base_demand =
            self.decode_arbiter_demand(demand_data.baseArbiter, &demand_data.baseDemand)?;

        Ok(DecodedRevocableArbiterComposingDemandData {
            base_arbiter,
            base_demand: Box::new(decoded_base_demand),
            revocable,
        })
    }
}
