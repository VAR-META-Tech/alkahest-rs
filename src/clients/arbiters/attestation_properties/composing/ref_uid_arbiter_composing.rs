use crate::clients::arbiters::DecodedDemand;
use crate::{
    clients::arbiters::ArbitersModule,
    contracts::attestation_properties::composing::RefUidArbiter::DemandData, impl_arbiter_api,
    impl_demand_data_conversions, impl_encode_and_decode,
};
use alloy::primitives::{Address, FixedBytes};

impl_demand_data_conversions!(DemandData);

/// Decoded version of RefUidArbiter::DemandData with actual demand structure instead of raw bytes
#[derive(Debug, Clone)]
pub struct DecodedRefUidArbiterComposingDemandData {
    /// Same base arbiter address as original
    pub base_arbiter: Address,
    /// Decoded base demand instead of raw bytes
    pub base_demand: Box<DecodedDemand>,
    /// Same refUID bytes32 as original
    pub ref_uid: FixedBytes<32>,
}

impl ArbitersModule {
    pub fn decode_ref_uid_arbiter_composing_demands(
        &self,
        demand_data: DemandData,
    ) -> eyre::Result<DecodedRefUidArbiterComposingDemandData> {
        let base_arbiter = demand_data.baseArbiter;
        let ref_uid = demand_data.refUID;
        let decoded_base_demand =
            self.decode_arbiter_demand(demand_data.baseArbiter, &demand_data.baseDemand)?;

        Ok(DecodedRefUidArbiterComposingDemandData {
            base_arbiter,
            base_demand: Box::new(decoded_base_demand),
            ref_uid,
        })
    }
}
