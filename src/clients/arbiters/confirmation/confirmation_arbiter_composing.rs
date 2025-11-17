use crate::clients::arbiters::DecodedDemand;
use crate::{
    clients::arbiters::ArbitersModule,
    contracts::confirmation_arbiters::ConfirmationArbiterComposing::DemandData, impl_arbiter_api,
    impl_demand_data_conversions, impl_encode_and_decode,
};
use alloy::primitives::Address;

impl_demand_data_conversions!(DemandData);

/// Decoded version of ConfirmationArbiterComposing::DemandData with actual demand structure instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedConfirmationArbiterComposingDemandData {
    /// Same base arbiter address as original
    pub base_arbiter: Address,
    /// Decoded base demand instead of raw bytes
    pub base_demand: Box<DecodedDemand>,
}

impl ArbitersModule {
    pub fn decode_confirmation_arbiter_composing_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedConfirmationArbiterComposingDemandData> {
        let base_arbiter = demand_data.baseArbiter;
        let decoded_base_demand =
            self.decode_arbiter_demand(demand_data.baseArbiter, &demand_data.baseDemand)?;

        Ok(DecodedConfirmationArbiterComposingDemandData {
            base_arbiter,
            base_demand: Box::new(decoded_base_demand),
        })
    }
}
