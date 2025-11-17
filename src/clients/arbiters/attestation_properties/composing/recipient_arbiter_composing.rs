use crate::clients::arbiters::DecodedDemand;
use crate::{
    clients::arbiters::ArbitersModule,
    contracts::attestation_properties::composing::RecipientArbiter::DemandData, impl_arbiter_api,
    impl_demand_data_conversions, impl_encode_and_decode,
};
use alloy::primitives::Address;

impl_demand_data_conversions!(DemandData);

/// Decoded version of RecipientArbiter::DemandData with actual demand structure instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedRecipientArbiterComposingDemandData {
    /// Same base arbiter address as original
    pub base_arbiter: Address,
    /// Decoded base demand instead of raw bytes
    pub base_demand: DecodedDemand,
    /// Same recipient address as original
    pub recipient: Address,
}

impl ArbitersModule {
    pub fn decode_recipient_arbiter_composing_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedRecipientArbiterComposingDemandData> {
        let base_arbiter = demand_data.baseArbiter;
        let recipient = demand_data.recipient;
        let decoded_base_demand =
            self.decode_arbiter_demand(demand_data.baseArbiter, &demand_data.baseDemand)?;

        Ok(DecodedRecipientArbiterComposingDemandData {
            base_arbiter,
            base_demand: decoded_base_demand,
            recipient,
        })
    }
}
