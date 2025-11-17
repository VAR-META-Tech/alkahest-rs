use crate::clients::arbiters::DecodedDemand;
use crate::{
    clients::arbiters::ArbitersModule,
    contracts::attestation_properties::composing::UidArbiter::DemandData,
    impl_demand_data_conversions,
};
use alloy::primitives::{Address, FixedBytes};

impl_demand_data_conversions!(DemandData);

/// Decoded version of UidArbiter::DemandData with actual demand structure instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedUidArbiterComposingDemandData {
    /// Same base arbiter address as original
    pub base_arbiter: Address,
    /// Decoded base demand instead of raw bytes
    pub base_demand: Box<DecodedDemand>,
    /// Same uid bytes32 as original
    pub uid: FixedBytes<32>,
}

impl ArbitersModule {
    pub fn decode_uid_arbiter_composing_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedUidArbiterComposingDemandData> {
        let base_arbiter = demand_data.baseArbiter;
        let uid = demand_data.uid;
        let decoded_base_demand =
            self.decode_arbiter_demand(demand_data.baseArbiter, &demand_data.baseDemand)?;

        Ok(DecodedUidArbiterComposingDemandData {
            base_arbiter,
            base_demand: Box::new(decoded_base_demand),
            uid,
        })
    }
}
